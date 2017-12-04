#!/usr/bin/env luajit
local dns, rrparser = require('dns'), require('dns.rrparser')
local nb, utils = require('dns.nbio'), require('dns.utils')
local ffi = require('ffi')

local function log(msg, ...)
	print('[info] ' .. string.format(msg, ...))
end
local function panic(msg, ...)
	error('[panic] ' .. string.format(msg, ...))
end

-- Add RR to packet and send it out if it's full
local function add_rr(socket, msg, answer, rr)
	if not answer:put(rr, true) then
		assert(nb.tcpsend(socket, answer))
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
		error('invalid character in: ' .. name)
	end
	local zonefile = name .. 'zone'
	local mtime = dns.utils.mtime(zonefile)
	if mtime == 0 then return end
	return zonefile, mtime
end

-- Serve requests
local function zone_transfer(sock, parser)
	-- Parse inbound query message
	local query = dns.packet(512)
	local msg, err = nb.tcprecv(sock, query)
	if not msg then error(err) end
	if not query:parse() then
		error('query parse error')
	end
	local tstart = nb.now()
	local name = query:qname():tostring()
	local zonefile, mtime = zone_get(name)
	local answer = dns.packet(20*1024)
	query:toanswer(answer)
	-- Not authoritative for this zone
	if not zonefile then
		log('%s: refused (no zone found)', name)
		answer:rcode(dns.rcode.REFUSED)
	-- Not a transfer request
	elseif query:qtype() ~= dns.type.AXFR and query:qtype() ~= dns.type.IXFR then
		answer:rcode(dns.rcode.SERVFAIL)
	else
		answer:aa(true)
		assert(parser:open(zonefile))
		local soa, nrrs, npkts = nil, 0, 0
		local rrset = ffi.gc(dns.rrset(nil, 0), dns.rrset.clear)
		rrset.raw_owner = dns.todname(parser.r_owner)
		-- Stream zone to requestor
		log('%s: stream start (mtime %d)', zonefile, mtime)
		while parser:parse() do
			rrset.raw_type = parser.r_type
			rrset:add(parser.r_data, parser.r_ttl, parser.r_data_length)
			nrrs = nrrs + 1
			npkts = npkts + add_rr(sock, query, answer, rrset)
			if not soa and rrset:type() == dns.type.SOA then
				soa = rrset:copy()
			end
			rrset:clear()
		end
		log('%s: stream end (%d records, %d messages, %d msec)',
			 zonefile, nrrs, npkts, (nb.now() - tstart) * 1000.0)
		if soa then add_rr(sock, query, answer, soa) end
	end
	nb.tcpsend(sock, answer)
end

local function serve(sock)
	local parser = assert(rrparser.new())
	local ok, err = pcall(zone_transfer, sock, parser)
	if not ok then panic(err) end
	parser:reset()
	sock:close()
end

-- Parse arguments and start serving
for k,v in next,arg,0 do
	local chr = string.char(v:byte())
	if k < 1 then break
	elseif chr == '@' then
		local host, port = v:match("@([^#]+)"), v:match("#(%d+)") or 53
		local tcp = assert(nb.socket(nb.family(host), 'stream'))
		tcp:bind(host, port)
		nb.go(function ()
			while true do
				local ok, err = nb.go(serve, tcp:accept())
				if not ok then
					local chost, cport = tcp:getsockname()
					log('error', '%s#%d: %s', chost, cport, err)
				end
			end
		end)
	else
		local ok, err = utils.chdir(v..'/')
		if not ok then error(string.format('invalid pile path: %s (%s)', v, err)) end
	end
end

local ok, err = nb.run()
if not ok then panic(err) end