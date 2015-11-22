#!/usr/bin/env luajit
local kdns = require('kdns')
-- Parse parameters
local host, port, tcp = nil, 53, false
local version, dobit, bufsize = 0, false, nil
local qname, qtype, qclass = '.', kdns.type.NS, kdns.class.IN
local flags = {'rd'}
for k,v in pairs(arg) do
	local chr = string.char(v:byte())
	if chr == '@' then host = v:sub(2)
	elseif kdns.type[v] ~= nil then qtype = kdns.type[v]
	elseif kdns.class[v] ~= nil then qclass = kdns.class[v]
	elseif v == '-p' then k,v = next(arg, k) port = tonumber(v)
	elseif v == '-t' then tcp = true
	elseif v == '+cd' then table.insert(flags, 'cd')
	elseif v == '+do' then dobit = true
	else -- + Modifiers
		local match = v:match('+bufsize=(%d+)')
		if match ~= nil then bufsize = tonumber(match) end
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
local wire = kdns.io.query(query:towire(), host, tcp, port)
local answer = kdns.packet(#wire, wire)
if not answer then error('; NO ANSWER') end
if not answer:parse() then
	kdns.hexdump(wire)
	error('; MALFORMED MESSAGE')
end
print(answer, '\n')
-- Additional information
print(string.format(';; Query time: %d msec', 0))
print(string.format(';; SERVER: %s#%d', host, port))
print(string.format(';; WHEN: %s', os.date()))
print(string.format(';; MSG SIZE  rcvd: %d', #wire))
