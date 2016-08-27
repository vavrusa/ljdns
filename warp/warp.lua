#!/usr/bin/env luajit
local S = require('syscall')
local dns = require('dns')
local go, utils = require('dns.nbio'), require('dns.utils')
local gettime = go.now

-- Export stats about worker and answers
local stats, answers, worker = {}, {
	noerror = 0, nodata = 0, nxdomain = 0, servfail = 0, cached = 0, slow = 0, dnssec = 0,
}, {
	udp = 0, tcp = 0, queries = 0, dropped = 0,
}
for _, l in ipairs({1,10,50,100,250,500,1000,1500}) do answers[l .. 'ms'] = 0 end

-- Logging code
local vlog = function () end
local function log(req, level, msg, ...)
	if not msg then return end
	if req and type(req) == 'table' then
		req = string.format('%s#%d ', req.addr.addr, req.addr.port)
	end
	print(string.format('[%s] %s%s', level, req or '', string.format(msg, ...)))
end

-- TODO: fill this from config
local config = {
	bufsize = 4096,
	route = {
		{
			require('warp.route.lru').init(),
			require('warp.route.file').init(),
			require('warp.route.dnssec').init { algo = 'ecdsa_p256_sha256' },
		}
	}
}
-- Export HTTP interface
local has_http, http = pcall(require('warp.vendor.init').new, 'http', {
	title = 'DNS Warp',
	stats = {
		list = function ()
			local s = {}
			for k,v in pairs(stats) do s[k] = v end
			for k,v in pairs(answers) do s['answer.' .. k] = v end
			for k,v in pairs(worker) do s['worker.' .. k] = v end
			s['worker.concurrent'] = go.coroutines
			return s
		end,
	},
	worker = {
		id = 0,
		info = function ()
			local u = S.getrusage('self')
			return {pid = S.getpid(), rss=u.maxrss, usertime=u.utime.time,
					systime=u.stime.time, pagefaults=u.majflt, queries=0}
		end,
		stats = function () return worker end
	}
})

-- Run HTTP interface
if has_http and http then
	vlog(nil, 'https %s#%d: listening', '127.0.0.1', 8055)
	http.init()
	http.interface('127.0.0.1', 8055, http.endpoints)
	go(function ()
		local ok, err, timeout = true
		local pfd = http.pollfd()
		while ok do
			ok, err, timeout = http.step(0)
			if not ok then vlog(nil, err) end
			if timeout and timeout > 0.01 then
				go.block(pfd, timeout)
			end
		end
	end)
end

-- Pooled objects
local reqpool = {}
local function pool(list, elm)
	if #list < 256 then table.insert(list, elm) end
end
local function drain(list)
	return table.remove(list)
end
local function getrequest(sock, addr)
	local req = drain(reqpool) or {
		query = dns.packet(512),
		answer = dns.packet(4096),
		authority = {},
		additional = {},
	}
	req.log, req.vlog = log, vlog
	req.sock = sock
	req.addr = addr
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
	answers[rcode] = (answers[rcode] or 0) + 1
	-- Log by options
	if dns.edns.dobit(req.opt) then answers.dnssec = answers.dnssec + 1 end
	-- Log latency breakdown
	local lat = gettime(true) - req.now
	if     lat <= 0.001 then answers['1ms'] = answers['1ms'] + 1
	elseif lat <= 0.010 then answers['10ms'] = answers['10ms'] + 1
	elseif lat <= 0.050 then answers['50ms'] = answers['50ms'] + 1
	elseif lat <= 0.100 then answers['100ms'] = answers['100ms'] + 1
	elseif lat <= 0.250 then answers['250ms'] = answers['250ms'] + 1
	elseif lat <= 0.500 then answers['500ms'] = answers['500ms'] + 1
	elseif lat <= 1.000 then answers['1000ms'] = answers['1500ms'] + 1
	elseif lat <= 1.500 then answers['1500ms'] = answers['1500ms'] + 1
	else                     answers['slow'] = answers['slow'] + 1
	end
end

-- Parse message, then answer to client
local function serve(req, writer)
	if not req.query:parse() then
		worker.dropped = worker.dropped + 1
		error('query parse error')
	end
	worker.queries = worker.queries + 1
	local qtype = req.query:qtype()
	-- Set request meta
	req.xfer = (qtype == dns.type.AXFR or qtype == dns.type.IXFR)
	req.nocache = false
	req.now = gettime(true)
	req.stats = stats
	req.query:toanswer(req.answer)
	-- Copy OPT if present in query
	local opt = req.query.opt
	if opt ~= nil then
		local payload = math.min(dns.edns.payload(opt), config.bufsize)
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
		for _, r in ipairs(config.route[1]) do
			if r:serve(req, writer) == false then break end
		end
	end
	-- Add authority and additionals
	req.answer:begin(dns.section.AUTHORITY)
	for _, rr in ipairs(req.authority) do req.answer:put(rr, true) end
	req.answer:begin(dns.section.ADDITIONAL)
	for _, rr in ipairs(req.additional) do req.answer:put(rr, true) end
	-- Run complete handlers
	for _, r in ipairs(config.route[1]) do
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
	req.query:clear()
	req.sock, req.addr = nil, nil
	table.clear(req.authority)
	table.clear(req.additional)
	pool(reqpool, req)
end

-- Writer closures for UDP and TCP
local function writer_udp(req, msg)
	return go.udpsend(req.sock, msg.wire, msg.size, req.addr)
end
local function writer_tcp(req, msg)
	return go.tcpsend(req.sock, msg.wire, msg.size)
end

-- TCP can pipeline multiple queries in single connection
local function read_tcp(sock)
	local addr, queries = sock:getpeername(), 0
	while true do
		local req = getrequest(sock, addr)
		-- Read query off socket
		local ok, err = go.tcprecv(sock, req.query.wire, req.query.max_size)
		if ok == 0 then break end
		if err then req:log('error', err) break end
		-- Spawn off new coroutine for request
		if queries > 0 then req.sock = sock:dup() end
		worker.tcp = worker.tcp + 1
		req.query.size = ok
		req.is_tcp = true
		ok, err = go(serve, req, writer_tcp)
		if not ok then req:log('error', err) end
		queries = queries + 1
	end
	-- Do not wait for GC
	sock:close()
end

-- Bind to sockets and start serving
local function downstream(host, port)
	-- Create bound sockets
	local msg, addr = string.format('interface "%s#%d: ', host, port), go.addr(host, port)
	local tcp, err = go.socket(addr, true)
	if not tcp then error(msg..err) end
	local udp, err = go.socket(addr)
	if not udp then error(msg..err) end
	vlog(nil, msg .. 'listening')
	-- Spawn coroutines for listeners
	go(function()
		local addr, ok, err = udp:getsockname(), 0
		while ok do
			-- Fetch next request off freelist
			local req = getrequest(udp, addr)
			ok, err = go.udprecv(udp, req.query.wire, req.query.max_size, addr)
			if ok then
				worker.udp = worker.udp + 1
				req.addr = addr
				req.is_tcp = false
				req.query.size = ok
				ok, err = go(serve, req, writer_udp)
			end
			if err then req:log('error', tostring(err)) end
		end
	end)
	go(function ()
		local addr, ok, err = tcp:getsockname(), 0
		while ok do
			ok, err = go(read_tcp, go.accept(tcp))
			if err then log({addr=addr}, 'error', tostring(err)) end
		end
	end)
end

local function help()
	print(string.format('Usage: %s [options] <config>', arg[0]))
	print('Options:')
	print('\t-h,--help        ... print this help')
	print('\t-v               ... verbose logging')
	print('\t@<addr>[#port]   ... listen on given address/port (e.g. ::1#53)')
end

-- Parse arguments and start serving
for k,v in next,arg,0 do
	local chr = string.char(v:byte())
	if k < 1 then break
	elseif chr == '@' then
		local host, port = v:match("@([^#]+)"), tonumber(v:match("#(%d+)")) or 53
		downstream(host, port)
	elseif v == '-v' then
		vlog = function (req, ...) return log(req, 'info', ...) end
	elseif v == '-h' or v == '--help' then
		help()
		return 0
	else
		local ok, err = utils.chdir(v..'/')
		if not ok then error(string.format('invalid pile path: %s (%s)', v, err)) end
	end
end

-- Enable trace stitching
require('jit.opt').start('minstitch=2')
-- Run coroutines
local ok, err = go.run(1)
if not ok then
	log(nil, 'error', err)
end
