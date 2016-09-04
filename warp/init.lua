local dns = require('dns')
local gettime = os.time

-- Logging code
local function log(req, level, msg, ...)
	if not msg then return end
	if req and type(req) == 'table' then
		req = string.format('%s#%d ', req.addr.addr, req.addr.port)
	end
	print(string.format('[%s] %s%s', level, req or '', string.format(msg, ...)))
end

-- Export stats and latency information
local stats = {
	udp = 0, tcp = 0, queries = 0, dropped = 0,
	noerror = 0, nodata = 0, nxdomain = 0, servfail = 0,
	cached = 0, slow = 0, dnssec = 0,
}
local latency = {} for _, l in ipairs({1,10,50,100,250,500,1000,1500,3000}) do
	latency[l] = 0
end

-- Export module
local M = {
	-- Config options
	bufsize = 4096,
	max_pool = 256,
	max_query = 512,
	max_answer = 4096,
	-- Logging
	log = log, vlog = function () end,
	-- Metrics
	stats = stats, latency = latency,
	-- Routes
	routes = {},
}

-- Pooled objects
local rqpool, rqpool_len = {}, 0
local function drain()
	local rq
	if rqpool_len > 0 then
		rqpool_len = rqpool_len - 1
		rq = table.remove(rqpool)
	else
		rq = {
			query = dns.packet(M.max_query),
			answer = dns.packet(M.max_answer),
			authority = {},
			additional = {},
		}
	end
	return rq
end

local function recycle(r)
	r.sock, r.addr = nil, nil
	if rqpool_len < M.max_pool then
		-- Clear the packet buffer and lists
		r.query:clear()
		table.clear(r.authority)
		table.clear(r.additional)
		-- Put to freelist
		table.insert(rqpool, r)
		rqpool_len = rqpool_len + 1
	end
end
M.release = recycle

--
-- Public interface
--

-- Get a new request
function M.request(sock, addr, tcp)
	local req = drain()
	req.sock, req.addr = sock, addr
	req.log, req.vlog = M.log, M.vlog
	req.is_tcp = tcp
	return req
end

-- Log answer and update metrics
local function log_answer(req)
	-- Log by RCODE
	local rcode = req.answer:rcode()
	if rcode == 0 and req.answer:ancount() == 0 then
		rcode = 'nodata'
	else
		rcode = string.lower(dns.tostring.rcode[rcode])
	end
	stats[rcode] = (stats[rcode] or 0) + 1
	-- Log by options
	if dns.edns.dobit(req.opt) then stats.dnssec = stats.dnssec + 1 end
	-- Log latency breakdown
	local lat = gettime() - req.now
	if     lat <= 0.001 then latency[1] = latency[1] + 1
	elseif lat <= 0.010 then latency[10] = latency[10] + 1
	elseif lat <= 0.050 then latency[50] = latency[50] + 1
	elseif lat <= 0.100 then latency[100] = latency[100] + 1
	elseif lat <= 0.250 then latency[250] = latency[250] + 1
	elseif lat <= 0.500 then latency[500] = latency[500] + 1
	elseif lat <= 1.000 then latency[1000] = latency[1500] + 1
	elseif lat <= 1.500 then latency[1500] = latency[1500] + 1
	else                     latency[3000] = latency[3000] + 1
	end
end

-- Parse message, then answer to client
function M.serve(req, writer)
	if not req.query:parse() then
		stats.dropped = stats.dropped + 1
		error('query parse error')
	end
	-- Update client type metrics
	stats.queries = stats.queries + 1
	if req.is_tcp then
		stats.tcp = stats.tcp + 1
	else
		stats.udp = stats.udp + 1
	end
	local qtype = req.query:qtype()
	-- Set request meta
	req.xfer = (qtype == dns.type.AXFR or qtype == dns.type.IXFR)
	req.soa = nil
	req.nocache = false
	req.now = gettime()
	req.stats = stats
	req.query:toanswer(req.answer)
	-- Copy OPT if present in query
	local opt = req.query.opt
	if opt ~= nil then
		local payload = math.min(dns.edns.payload(opt), M.bufsize)
		-- Reuse to save memory allocations
		if req.optbuf then
			req.opt = req.optbuf
			dns.edns.init(req.opt, 0, payload)
		else
			req.opt = dns.edns.rrset(0, payload)
		end
	end
	-- Do not process transfers over UDP
	if req.xfer and not req.is_tcp then
		req.answer:tc(true)
	else
		for _, r in ipairs(M.routes[1]) do
			if r:serve(req, writer) == false then break end
		end
	end
	-- Add authority and additionals
	req.answer:begin(dns.section.AUTHORITY)
	for _, rr in ipairs(req.authority) do req.answer:put(rr, true) end
	req.answer:begin(dns.section.ADDITIONAL)
	for _, rr in ipairs(req.additional) do req.answer:put(rr, true) end
	-- Run complete handlers
	for _, r in ipairs(M.routes[1]) do
		if r.complete then r:complete(req) end
	end
	log_answer(req)
	-- Serialize OPT if present
	if req.opt then
		req.answer:put(req.opt, true)
		req.optbuf, req.opt = req.opt, nil
	end
	-- Finalize answer and stream it
	writer(req, req.answer)
	recycle(req)
end

-- Form route
function M.route(zone, t)
	if type(zone) == 'table' and not t then
		t, zone = zone, 1
	end
	M.routes[zone] = t
	return M
end

function M.conf(conf)
	local ok
	if type(conf) ~= 'function' then
		ok, conf = pcall(loadfile, conf)
		if not ok or not conf then
			return nil, conf
		end
	end
	local env = {conf = M, route = M.route}
	env = setmetatable(env, {
		__index = function (t,k)
			local v = rawget(t, k) or _G[k]
			if not v then
				v = require('warp.route')[k]
				if v then v = v.init end
			end
			return v
		end
	})
	setfenv(conf, env)
	conf()
end

return M