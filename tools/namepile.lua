#!/usr/bin/env luajit
-- This is a simple daemon that provides zone transfers for a pile of zones
-- It expects to find files ending with .zone, zones are parsed and streamed on demand,
-- so free startup time and no memory requirements.
-- Example:
-- $ mkdir pile
-- $ echo "$ORIGIN example" > pile/example.zone
-- $ echo "@ 3600 IN SOA dns hostmaster 0 10800 3600 1209600 60" >> pile/example.zone
-- $ echo -e "@ 3600 IN NS ns1\nns1 3600 IN A 1.2.3.4" >> pile/example.zone
-- $ namepile.lua -v pile @127.0.0.1#4242 &
-- $ dig.lua AXFR @127.0.0.1#4242 example.
local kdns, rrparser = require('dns'), require('dns.rrparser')
local go, utils = require('dns.aio'), require('dns.utils')
local ffi = require('ffi')
local vlog = function () end
local function log(level, addr, msg, ...)
	local peer_id = addr and string.format('%s#%d ', addr.addr, addr.port) or ''
	print(string.format('[%s] %s%s', level, peer_id, string.format(msg, ...)))
end

-- Add RR to packet and send it out if it's full
local function add_rr(socket, msg, answer, rr)
	if not answer:put(rr, true) then
		assert(go.tcpsend(socket, answer:towire()))
		msg:toanswer(answer)
		answer:aa(true)
		answer:put(rr, true) -- Promise not to access RR afterwards
		return 1
	end
	return 0
end

-- Find appropriate zonefile and mtime for this query
local function zone_get(name)
	if name:find('/', 1, true) or name:find('..', 1, true) then
		error('invalid character in: '..name)
	end
	local zonefile = name..'zone'
	local mtime = kdns.utils.mtime(zonefile)
	if mtime == 0 then zonefile = nil end
	return zonefile, mtime
end

-- Serve requests
local function zone_transfer(sock, addr, parser)
	-- Parse inbound query message
	local msg, err = go.tcprecv(sock)
	if not msg then error(err) end
	local query, tstart = kdns.packet(#msg, msg), go.now()
	if not query:parse() then
		error('query parse error')
	end
	local name = query:qname():tostring()
	local zonefile, mtime = zone_get(name)
	local answer = kdns.packet(20*1024)
	query:toanswer(answer)
	-- Not authoritative for this zone
	if not zonefile then
		vlog(addr, '%s: refused (no zone found)', name)
		answer:rcode(kdns.rcode.REFUSED)
	-- Not a transfer request
	elseif query:qtype() ~= kdns.type.AXFR and query:qtype() ~= kdns.type.IXFR then
		answer:rcode(kdns.rcode.SERVFAIL)
	else
		answer:aa(true)
		assert(parser:open(zonefile))
		local found, soa, nrrs, npkts = false, nil, 0, 0
		local rrset = ffi.gc(kdns.rrset(nil, 0), kdns.rrset.clear)
		rrset.raw_owner = kdns.todname(parser.r_owner)
		-- Stream zone to requestor
		vlog(addr, '%s: stream start (mtime %d)', zonefile, mtime)
		while parser:parse() do
			rrset.raw_type = parser.r_type
			rrset:add(parser.r_data, parser.r_ttl, parser.r_data_length)
			nrrs = nrrs + 1
			npkts = npkts + add_rr(sock, query, answer, rrset)
			if not soa and rrset:type() == kdns.type.SOA then
				soa = rrset:copy()
			end
			rrset:clear()
		end
		vlog(addr, '%s: stream end (%d records, %d messages, %d msec)',
			 zonefile, nrrs, npkts, (go.now() - tstart) * 1000.0)
		if soa then add_rr(sock, query, answer, soa) end
	end
	go.tcpsend(sock, answer:towire())
end
local function serve(sock)
	local addr = sock:getpeername()
	local parser = assert(rrparser.new())
	local ok, err = pcall(zone_transfer, sock, addr, parser)
	if err then log('error', addr, tostring(err)) end
	parser:reset()
	sock:close()
end

-- Parse arguments and start serving
for k,v in next,arg,0 do
	local chr = string.char(v:byte())
	if k < 1 then break
	elseif chr == '@' then
		local host, port = v:match("@([^#]+)"), v:match("#(%d+)") or 53
		local msg = string.format('interface "%s#%d: ', host, port)
		local addr = go.addr(host, port)
		-- Create bound sockets and spawn coroutines
		local tcp, err = go.socket(addr, true)
		if not tcp then error(msg..err) end
		go(function ()
			vlog(tcp:getsockname(), 'listening')
			while true do
				local ok, err = go(serve, go.accept(tcp))
				if not ok then log('error', tcp:getsockname(), err) end
			end
		end)
	elseif v == '-v' then
		vlog = function (...) return log('info', ...) end
	else
		local ok, err = utils.chdir(v..'/')
		if not ok then error(string.format('invalid pile path: %s (%s)', v, err)) end
	end
end
local ok, err = go.run()
if err then
	log('error', nil, nil, err)
end