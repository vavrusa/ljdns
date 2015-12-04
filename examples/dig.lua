#!/usr/bin/env luajit
local kdns = require('kdns')
-- Parse parameters
local host, port, tcp, key = nil, 53, false, nil
local version, dobit, bufsize, short = 0, false, nil, false
local qname, qtype, qclass = '.', kdns.type.NS, kdns.class.IN
local flags = {'rd'}
for k,v in next,arg,0 do
	local chr = string.char(v:byte())
	if k < 1 then break
	elseif chr == '@' then host = v:sub(2)
	elseif kdns.type[v] ~= nil then
		qtype = kdns.type[v]
		if qtype == kdns.type.AXFR or qtype == kdns.type.IXFR then tcp = true end
	elseif kdns.class[v] ~= nil then qclass = kdns.class[v]
	elseif v == '-p' then k,v = next(arg, k) port = tonumber(v)
	elseif v == '-y' then k,v = next(arg, k) key = kdns.tsig(v)
	elseif v == '+short' then short = true
	elseif v == '+tcp' then tcp = true
	elseif v == '+cd' then table.insert(flags, 'cd')
	elseif v == '+do' or v == '+dnssec' then dobit = true
	elseif v == '-h' or v == '--help' then
		print(string.format('Usage: %s [options] [@server] [type] [class] [domain]', arg[0]))
		print('Options:')
		print('\t-p <num>  server port number (default: 53)')
		print('\t-y <tsig> use TSIG key (default: none, example: "testkey:hmac-md5:Wg==")')
		print('\t+tcp      use TCP for transport')
		print('\t+short    print only answer records')
		print('\t+cd       DNSSEC checking disabled')
		print('\t+do       request DNSSEC records')
		print('Examples:')
		print('  ',arg[0],'NS cz +do')
		print('  ',arg[0],'@2001:678:f::1 AAAA nic.cz +tcp')
		print('  ',arg[0],'-y xfrkey:hmac-md5:Wg== @127.0.0.1 -p 5353 AXFR nic.cz')
		return 0
	else -- + Modifiers
		local match = v:match('+bufsize=(%d+)')
		if match ~= nil then bufsize = tonumber(match)
		else qname = v
		end
	end
end
if host == nil then for line in io.lines('/etc/resolv.conf') do
	host = line:match('nameserver ([0-9A-Za-z.:]+)')
	if host ~= nil then break end
end end
-- Create a query and send
local query = kdns.packet(512)
for i,flag in ipairs(flags) do query[flag](query, true) end
query:question(kdns.dname.parse(qname), qtype, qclass)
if dobit or (bufsize ~= nil and bufsize > 0) then
	if bufsize == nil then bufsize = 4096 end
	query:begin(kdns.section.ADDITIONAL)
	local rr = kdns.edns.rrset(version, bufsize)
	kdns.edns.dobit(rr, dobit)
	query:put(rr)
end
if key ~= nil then
	key:sign(query)
end
local elapsed = kdns.io.now()
local sock = assert(kdns.io.client(host, port, tcp))
kdns.io.send(query:towire(), sock)
sock:shutdown('send')
-- Start receiving answers
local rcvd, npkts, wire, tsig_ok = 0, 0, kdns.io.recv(sock), true
while wire ~= nil do
	local answer = kdns.packet(#wire, wire)
	if not answer then error('; NO ANSWER') end
	if not answer:parse() then
		kdns.hexdump(wire)
		error('; MALFORMED MESSAGE')
	end
	print(answer:tostring(short or npkts > 0))
	rcvd = rcvd + #wire
	npkts = npkts + 1
	if key ~= nil and not key:verify(answer) then tsig_ok = false break end
	wire = tcp and kdns.io.recv(sock) or nil
end
elapsed = kdns.io.now() - elapsed
-- Additional information
print(string.format(';; Query time: %d msec', elapsed * 1000.0))
print(string.format(';; SERVER: %s#%d', host, port))
print(string.format(';; WHEN: %s', os.date()))
print(string.format(';; MSG SIZE  rcvd: %d count: %d', rcvd, npkts))
if not tsig_ok then print(string.format(';; WARNING -- Some TSIG could not be validated')) end
