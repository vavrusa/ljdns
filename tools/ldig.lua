#!/usr/bin/env luajit
local dns = require('dns')
local nb = require('dns.nbio')
local ffi = require('ffi')

-- Parse parameters
local host, port, tcp, tls, xfer, key, cookie, https = nil, 53, false, false, false, nil, nil
local version, dobit, bufsize, short, multi = 0, false, nil, false
local qname, qtype, qclass = '.', dns.type.NS, dns.class.IN
local flags = {'rd'}
local k = 1 while k <= #arg do
	local v = arg[k]
	local chr = string.char(v:byte())
	if chr == '@' then host = v:sub(2)
	elseif dns.type[v] ~= nil then
		qtype = dns.type[v]
		if qtype == dns.type.AXFR or qtype == dns.type.IXFR then
			xfer, tcp = true, true
		end
	elseif dns.class[v] ~= nil then qclass = dns.class[v]
	elseif v == '-' then multi = true
	elseif v == '-f' then short, k = arg[k + 1], k + 1
	elseif v == '-p' then port, k = tonumber(arg[k + 1]), k + 1
	elseif v == '-y' then key, k = dns.tsig(arg[k + 1]), k + 1
	elseif v == '-x' then
		v, k = arg[k + 1], k + 1
		qtype, qname = dns.type.PTR, ''
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
	elseif v == '+tls' then
		tls, tcp = true, true
		if port == 53 then port = 853 end
	elseif v:find('+cookie',1) then
		cookie = v:match('+cookie=(%S+)') or true
	elseif v:find('+https',1) then
		https = v:match('+https=(%S+)') or true
	elseif v == '+cd' then table.insert(flags, 'cd')
	elseif v == '+do' or v == '+dnssec' then dobit = true
	elseif v == '-h' or v == '--help' then
		print(string.format('Usage: %s [options] [@server] [type] [class] [domain]', arg[0]))
		print('Options:')
		print('\t-p <num>  server port number (default: 53, 853 for +tls)')
		print('\t-y <tsig> use TSIG key (default: none, example: "testkey:hmac-md5:Wg==")')
		print('\t-x <ip>   do a reverse lookup')
		print('\t-f json   return DNS response as JSON')
		print('\t+tcp      use TCP for transport')
		print('\t+tls      use TLS for transport')
		print('\t+https=X  use HTTPS for transport')
		print('\t+short    print only answer records')
		print('\t+cd       DNSSEC checking disabled')
		print('\t+do       request DNSSEC records')
		print('\t+cookie   request a DNS COOKIE')
		print('\t+cookie=X pass a DNS COOKIE')
		print('\t-         read queries from stdin (pipelined if +tcp is passed)')
		print('Examples:')
		print('  ',arg[0] .. ' -x 192.168.1.1')
		print('  ',arg[0] .. ' NS cz +do')
		print('  ',arg[0] .. ' @2001:678:f::1 AAAA nic.cz +tcp')
		print('  ',arg[0] .. ' -y xfrkey:hmac-md5:Wg== @127.0.0.1 -p 5353 AXFR nic.cz')
		print('  ',arg[0] .. ' NS cz -f json | jq .')
		print('  ','echo -e "NS is\\nNS cz" | ' .. arg[0] .. ' +tcp -')
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
local queries, planned = {}, {}

-- Create a queries
if not multi then
	table.insert(planned, {qname, qtype, qclass})
else
	for line in io.lines() do
		local query = {'.',nil,nil}
		for w in line:gmatch('([^%s]+)') do
			if not query[3] and dns.class[w] then query[3] = dns.class[w]
			elseif not query[2] and dns.type[w] then query[2] = dns.type[w]
			else query[1] = w end
		end
		query[2] = query[2] or dns.type.A
		query[3] = query[3] or dns.class.IN
		table.insert(planned, query)
	end
end
for _,q in ipairs(planned) do
	local query = dns.packet(512)
	for _,flag in ipairs(flags) do query[flag](query, true) end
	query:question(dns.dname.parse(q[1]), q[2], q[3])
	if dobit or (bufsize ~= nil and bufsize > 0) or cookie then
		if bufsize == nil then bufsize = 4096 end
		query:begin(dns.section.ADDITIONAL)
		local rr = dns.edns.rrset(version, bufsize)
		dns.edns.dobit(rr, dobit)
		if cookie then
			local client = cookie
			-- Unpack cookie from hexstring
			if type(client) == 'string' then
				local hex = ''
				cookie:gsub('%w%w', function (c) hex = hex .. string.char(tonumber(c, 16)) end)
				client = hex
			-- Generate new client cookie
			else
				client = io.open('/dev/urandom', 'r'):read(8)
			end
			dns.edns.option(rr, dns.option.COOKIE, client)
		end
		query:put(rr)
	end
	if key ~= nil then
		key:sign(query)
	end
	table.insert(queries, query)
end

-- Send and wait for answers
local started = nb.now()
local send, recv = nb.udpsend, nb.udprecv
if tcp then
	send, recv = nb.tcpsend, nb.tcprecv
end

-- DNS over HTTPS wrapper
if https then
	local http_client = require('http.client')
	local new_headers = require('http.headers').new
	local http_tls = require('http.tls')
	local openssl_ctx = require('openssl.ssl.context')
	local streams = {}

	-- Switch nbio to cqueues as lua-http is using it
	local cq = require('cqueues').new()
	nb.go = function (f) return cq:wrap(f) or true end
	nb.run = function (t) return cq:loop(t) end

	-- Switch read/write functions to lua-http wrapper
	nb.socket = function ()
		-- Allow self-signed certificates
		local ctx = http_tls.new_client_context()
		ctx:setVerify(openssl_ctx.VERIFY_NONE)
		return http_client.connect {
			host = host,
			port = port,
			tls = true,
			sendname = https,
			version = 2,
			ctx = ctx,
		}
	end

	send = function (c, msg)
		local s = c:new_stream()
		local req_headers = new_headers()
		req_headers:append(":scheme", "https")
		req_headers:append(":authority", https)
		req_headers:upsert(":method", "POST")
		req_headers:append(":path", "/")
		-- https://tools.ietf.org/html/draft-hoffman-dns-over-https-01
		req_headers:upsert("content-type", "application/dns-udpwireformat")
		msg:id(0) -- Sec. 5, should use a DNS ID of 0
		s:write_headers(req_headers, false)
		s:write_chunk(msg:towire(), true)
		table.insert(streams, s)
	end

	recv = function (_, msg)
		local stream = table.remove(streams)
		local rcvd = 0
		for chunk in stream:each_chunk() do
			ffi.copy(msg.wire + rcvd, chunk)
			rcvd = rcvd + #chunk
		end

		return rcvd
	end


end

assert(nb.go(function()
	-- Make connection to destination
	local sock = nb.socket(nb.family(host), tcp and 'stream')
	if tcp and not tls then -- Attempt TFO
		-- We need to serialise message in a buffer prefixed with message length
		-- Convenience functions are unavailable and we can't use writev()
		local buf = ffi.new('uint8_t [?]', queries[1].size + 2)
		local txlen = ffi.cast('uint16_t *', buf)
		txlen[0] = dns.utils.n16(tonumber(queries[1].size))
		ffi.copy(buf + 2, queries[1].wire, queries[1].size)
		assert(sock:connect(host, port, buf, ffi.sizeof(buf)))
	else -- Make connected socket and send query
		if not https then
			assert(sock:connect(host, port))
			if tls then -- Upgrade to TLS
				sock = assert(require('dns.tls').client(sock, 'x509'))
			end
		end
		send(sock, queries[1])
	end
	for i=2,#queries do send(sock, queries[i]) end
	-- Start receiving answers
	for _=1,#queries do
	local answer = dns.packet(65535)
	local rcvd = recv(sock, answer)
	local nbytes, npkts, tsig_ok, soa = 0, 0, true, nil
	while rcvd and rcvd > 0 do
		answer.size = rcvd
		if not answer:parse() then
			print(dns.hexdump(answer:towire()))
			error('; MALFORMED MESSAGE')
		end
		if key ~= nil and not key:verify(answer) then
			tsig_ok = false
			break
		end
		-- Print packet
		local res = answer:tostring(short or npkts > 0)
		if #res > 0 then io.write(res) end
		nbytes, npkts = nbytes + tonumber(rcvd), npkts + 1
		-- Decide if we should wait for more packets
		if xfer then
			local rrs = answer:section(dns.section.ANSWER)
			if #rrs > 0 then
				local last = rrs[#rrs - 1]
				if not soa and rrs[0]:type() == dns.type.SOA then -- Starting SOA
					soa = dns.rdata.soa_serial(rrs[0]:rdata(0))
				elseif last:type() == dns.type.SOA then -- Ending SOA
					if soa == dns.rdata.soa_serial(last:rdata(0)) then
						break
					end
				end
			end
		end
		answer:clear()
		rcvd = xfer and recv(sock, answer) or 0
	end
	-- Additional information
	if not short then
		if #queries == 1 then
			assert(nbytes > 0, '; NO ANSWER')
		elseif nbytes <= 0 then
			print('; NO ANSWER')
		end
		local elapsed = nb.now() - started
		print(string.format(';; Query time: %d msec', elapsed * 1000.0))
		print(string.format(';; SERVER: %s#%d', host, port))
		print(string.format(';; WHEN: %s', os.date()))
		print(string.format(';; MSG SIZE  rcvd: %d count: %d', nbytes, npkts))
		if not tsig_ok then print(string.format(';; WARNING -- Some TSIG could not be validated')) end
	end
	end
end))
return assert(nb.run(3))
