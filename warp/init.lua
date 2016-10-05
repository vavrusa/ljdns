local ffi = require('ffi')
local dns = require('dns')
local gettime = require('dns.nbio').now

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
	hosts = {},
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
	req.session = nil
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
	local lat = (gettime() - req.now) * 1000
	local bucket = dns.utils.bucket(lat)
	latency[bucket] = latency[bucket] + 1
	req:vlog('answered as %s, %.02fms', rcode, lat)
end

-- Find route for received query
local function getroute(req, qname, iface)
	if not iface then
		return M.routes.default
	else
		local route, p = nil, qname.bytes
		for _ = 1, qname:labels() do
			route = iface.match[ffi.string(p)]
			if route then break end
			p = p + (p[0] + 1)
		end
		return route
	end
end

-- Parse message, then answer to client
function M.serve(req, writer, iface)
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
	local qname, qtype = req.query:qname(), req.query:qtype()
	-- Find best route for query
	local route = getroute(req, qname, iface)
	-- Set request meta
	local answer = req.answer
	req.xfer = (qtype == dns.type.AXFR or qtype == dns.type.IXFR)
	req.qname, req.qtype = qname, qtype
	req.soa = nil
	req.nocache = false
	req.now = gettime()
	req.stats = stats
	req.query:toanswer(answer)
	-- Answer request if it's routable
	if route then
		local opt = req.query.opt
		if opt ~= nil then -- Copy OPT if present in query
			local payload = math.min(dns.edns.payload(opt), M.bufsize)
			-- Reuse to save memory allocations
			if req.optbuf then
				req.opt = req.optbuf
				dns.edns.init(req.opt, 0, payload)
			else
				req.opt = dns.edns.rrset(0, payload)
			end
			req.answer.opt = req.opt
		end
		-- Do not process transfers over UDP
		if req.xfer and not req.is_tcp then
			req:vlog('zone transfer over udp, rejected')
			answer:tc(true)
		else
			route.serve(req, writer)
		end
		-- Add authority and additionals
		answer:begin(dns.section.AUTHORITY)
		for _, rr in ipairs(req.authority) do answer:put(rr, true) end
		answer:begin(dns.section.ADDITIONAL)
		for _, rr in ipairs(req.additional) do answer:put(rr, true) end
		-- Run complete handlers
		route.complete(req)
	else
		answer:rcode(dns.rcode.REFUSED)
	end
	log_answer(req)
	-- Drop the empty answers
	if answer.size == 0 then
		recycle(req)
		return
	end
	-- Serialize OPT if present
	if req.opt then
		answer:put(req.opt, true)
		req.optbuf, req.opt = req.opt, nil
	end
	-- Finalize answer and stream it
	writer(req, answer)
	recycle(req)
end

-- Form route
function M.route(name, t)
	if type(name) == 'table' and not t then
		t, name = name, 'default'
	end
	-- Compile callback closures
	local serve, complete = function () return true end, function () end
	for _,r in ipairs(t) do
		-- serve() terminates if it returns false, otherwise it's chained
		if r.serve then
			local prev = serve
			serve = function (a, b) return prev(a, b) and r:serve(a, b) ~= false end
		end
		-- complete() is chained
		if r.complete then
			local prev = complete
			complete = function (a) prev(a) r:complete(a) end
		end
	end
	M.routes[name] = {name=name, route=t, serve=serve, complete=complete}
	return M
end

-- Form listen rule
function M.listen(host, t, o)
	if not host then host, t = '::#53', host end
	o = o or {}
	-- Parse scheme, hostname and port
	local scheme = host:match '^(%S+)://'
	if scheme then
		host = host:sub(#scheme + 4)
	end
	scheme = scheme or 'dns'
	local host, port = dns.utils.addrparse(host)
	-- Build routing table
	local tree, match = {}, {}
	assert(type(t) == 'table', 'expected listen([name,]{ ... })')
	for r,v in pairs(t) do
		for _,f in ipairs(v) do
			if type(f) == 'string' then
				f = assert(dns.dname.parse(f), 'invalid domain name: '..f)
				f = f:lower()
				local key = f:towire():sub(1, #f - 1)
				match[key] = M.routes[r]
			end
			table.insert(tree, f)
		end
	end
	-- Create new interface
	local interface = {host=host, port=port, scheme=scheme, opt=o, tree=tree, match=match}
	table.insert(M.hosts, interface)
	return interface
end

function M.conf(conf)
	local ok
	if type(conf) ~= 'function' then
		ok, conf = pcall(loadfile, conf)
		if not ok or not conf then
			return nil, conf
		end
	end
	local env = {conf = M, route = M.route, listen = M.listen}
	env = setmetatable(env, {
		__index = function (t,k)
			local v = rawget(t, k) or _G[k]
			-- Implicit global: route type
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