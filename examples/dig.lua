#!/usr/bin/env luajit
local kdns = require('kdns')
-- Parse parameters
local host, port, tcp, xfer, key = nil, 53, false, false, nil
local version, dobit, bufsize, short = 0, false, nil, false
local qname, qtype, qclass = '.', kdns.type.NS, kdns.class.IN
local flags = {'rd'}
k = 1 while k <= #arg do
	local v = arg[k]
	local chr = string.char(v:byte())
	if chr == '@' then host = v:sub(2)
	elseif kdns.type[v] ~= nil then
		qtype = kdns.type[v]
		if qtype == kdns.type.AXFR or qtype == kdns.type.IXFR then
			xfer, tcp = true, true
		end
	elseif kdns.class[v] ~= nil then qclass = kdns.class[v]
	elseif v == '-p' then port, k = tonumber(arg[k + 1]), k + 1
	elseif v == '-y' then key, k = kdns.tsig(arg[k + 1]), k + 1
	elseif v == '-x' then
		v, k = arg[k + 1], k + 1
		qtype, qname = kdns.type.PTR, ''
		if v:find('.', 1, true) then
			for i in v:gmatch('[^.]+') do
				qname = string.format('%s%s.', qname, i)
			end
			qname = qname .. 'in-addr.arpa'
		else
			local part, through = '', false
			for i in v:gmatch('[^:]*') do
				if #i == 0 then
					if through then
						qname, part = part, ''
					end
					through = true
				else
					for c in string.format('%04s', i):gsub(' ', '0'):gmatch('.') do
						part = string.format('%s.%s', c, part)
					end
					through = false
				end
			end
			qname = part .. string.rep('0.', (64 - #qname - #part)/2) .. qname .. 'ip6.arpa'
		end
	elseif v == '+short' then short = true
	elseif v == '+tcp' then tcp = true
	elseif v == '+cd' then table.insert(flags, 'cd')
	elseif v == '+do' or v == '+dnssec' then dobit = true
	elseif v == '-h' or v == '--help' then
		print(string.format('Usage: %s [options] [@server] [type] [class] [domain]', arg[0]))
		print('Options:')
		print('\t-p <num>  server port number (default: 53)')
		print('\t-y <tsig> use TSIG key (default: none, example: "testkey:hmac-md5:Wg==")')
		print('\t-x <ip>   do a reverse lookup')
		print('\t+tcp      use TCP for transport')
		print('\t+short    print only answer records')
		print('\t+cd       DNSSEC checking disabled')
		print('\t+do       request DNSSEC records')
		print('Examples:')
		print('  ',arg[0],'-x 192.168.1.1')
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
	k = k + 1
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

-- Send and wait for answers
local go = require('kdns.aio')
local addr, elapsed = go.addr(host, port), go.now()
local send, recv = go.udpsend, go.udprecv
if tcp then send, recv = go.tcpsend, go.tcprecv end
assert(go(function()
	-- Make connection to destination
	local sock = go.socket(addr.family, tcp)
	if tcp then -- Attempt TFO
		go.connect(sock, addr, query:towire())
	else -- Make UDP connected socket and send query
		go.connect(sock, addr)
		send(sock, query:towire())
	end
	-- Start receiving answers
	local answer = kdns.packet(65535)
	local rcvd = recv(sock, answer.wire, answer.max_size)
	local nbytes, npkts, tsig_ok, soa = 0, 0, true, nil
	while rcvd and rcvd > 0 do
		answer.size = rcvd
		if not answer:parse() then
			print(kdns.hexdump(answer:towire()))
			error('; MALFORMED MESSAGE')
		end
		if key ~= nil and not key:verify(answer) then
			tsig_ok = false
			break
		end
		-- Print packet
		print(answer:tostring(short or npkts > 0))
		nbytes, npkts = nbytes + tonumber(rcvd), npkts + 1
		-- Decide if we should wait for more packets
		if xfer then
			local answer = answer:section(kdns.section.ANSWER)
			if #answer > 0 then
				local last = answer[#answer - 1]
				if not soa and answer[0]:type() == kdns.type.SOA then -- Starting SOA
					soa = kdns.rdata.soa_serial(answer[0]:rdata(0))
				elseif last:type() == kdns.type.SOA then -- Ending SOA
					if soa == kdns.rdata.soa_serial(last:rdata(0)) then
						break
					end
				end
			end
		end
		answer:clear()
		rcvd = xfer and recv(sock, answer.wire, answer.max_size) or 0
	end
	assert(nbytes > 0, '; NO ANSWER')
	elapsed = go.now() - elapsed
	-- Additional information
	print(string.format(';; Query time: %d msec', elapsed * 1000.0))
	print(string.format(';; SERVER: %s#%d', host, port))
	print(string.format(';; WHEN: %s', os.date()))
	print(string.format(';; MSG SIZE  rcvd: %d count: %d', nbytes, npkts))
	if not tsig_ok then print(string.format(';; WARNING -- Some TSIG could not be validated')) end
end))
return assert(go.run(3))