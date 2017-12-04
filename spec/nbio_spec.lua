describe('nbio', function()

	local ffi = require('ffi')
	local nb = require('dns.nbio')
	local dns = require('dns')
	local S = require('syscall')

	local function socketpair(socktype)
		local ok, err, s1, s2 = S.socketpair('unix', socktype)
		assert.truthy(ok, err)
		s1:nonblock()
		s2:nonblock()
		local r = nb.socket_t(s1:nogc():getfd(), 0)
		local w = nb.socket_t(s2:nogc():getfd(), 0)
		return r, w
	end

	it('parses address', function ()
		assert.truthy(nb.family('127.0.0.1'))
		assert.truthy(nb.family('::1'))
		assert.truthy(nb.family('/tmp/some.sock'))
	end)

	it('creates sockets', function ()
		for _,tcp in ipairs({'dgram', 'stream'}) do
			for _,k in ipairs({'inet','inet6','unix'}) do
				local s = nb.socket(k, tcp)
				assert.truthy(ffi.istype(nb.socket_t, s), string.format('creates %s/%s socket', k, tcp))
				s:close()
			end
		end
	end)

	it('supports stream sockets', function ()
		local r, w = socketpair('stream')
		-- Asynchronous read works
		assert.truthy(nb(function ()
			-- Compatibility
			assert.same('hello', r:receive(5))
			-- Pass buffer
			local buf = S.t.buffer(5)
			assert.same(5, r:receive(5, buf))
			assert.same('olleh', ffi.string(buf, 5))
			-- Timeout
			r:settimeout(500)
			-- local data, err = s:receive(5)
			-- assert.same(err, c.E.TIMEDOUT)
		end))
		-- Asynchronous write works
		assert.truthy(nb(function ()
			assert.same(5, w:send 'hello')
			assert.same(5, w:send 'olleh')
		end))
		assert.truthy(nb.run())
	end)

	-- Test independent send and receive
	local function sendreceive(socktype, send, recv)
		local r, w = socketpair(socktype)
		local dname = dns.dname('\4test')
		assert.truthy(nb(function ()
			local msg = dns.packet(512)
			msg:question(dname, dns.type.SOA)
			assert.truthy(send(w, msg))
		end))
		assert.truthy(nb(function ()
			local msg = dns.packet(512)
			assert.truthy(recv(r, msg))
			assert.truthy(msg:parse())
			assert.same(dname, msg:qname())
			assert.same(dns.type.SOA, msg:qtype())
		end))
		assert.truthy(nb.run())
	end

	it('sending and receiving DNS over UDP', function ()
		sendreceive('dgram', nb.udpsend, nb.udprecv)
	end)

	it('sending and receiving DNS over TCP', function ()
		sendreceive('stream', nb.tcpsend, nb.tcprecv)
	end)

	it('can do message ping/pong', function ()
		local server = nb.socket('inet', 'stream')
		server:bind('127.0.0.1', 0)
		-- Function sends PING to client, expects PONG back
		assert.truthy(nb(function ()
			local client = server:accept()
			local ret = client:receive(4)
			assert.same('PING', ret)
			client:send('PONG')
		end))
		assert.truthy(nb(function ()
			local client = nb.socket('inet', 'stream')
			local host, port = server:getsockname()
			client:connect(host, port, 'PING')
			local msg, _ = client:receive(4)
			assert.same('PONG', msg)
		end))
		assert.truthy(nb.run())
	end)

	-- Test pipelined message exchange
	local function exchange(socktype, send, recv, xchg, count)
		local r, w = socketpair(socktype)
		local dname = dns.dname('\4test')
		-- Spawn coroutine for each exchange
		for i = 1, count do
			local resp = dns.packet(32)
			assert.truthy(nb(function ()
				local query = dns.packet(32)
				query:id(i)
				query:question(dname, dns.type.SOA)
				assert.truthy(xchg(w, query, resp))
				assert.truthy(resp:parse())
				assert.same(query.size, resp.size)
				assert.same(query:qtype(), resp:qtype())
				assert.same(query:qname(), resp:qname())
			end))
		end
		-- Generate out-of-order responses
		assert.truthy(nb(function ()
			local rcvd = {}
			local msg = dns.packet(32)
			for _ = 1, count do
				assert.truthy(recv(r, msg))
				assert.truthy(msg:parse())
				table.insert(rcvd, msg:id())
			end
			assert.same(count, #rcvd)
			for _ = 1, count do
				local id = table.remove(rcvd, math.random(1, #rcvd))
				msg:id(id)
				msg:qr(true)
				assert.same(msg.size, send(r, msg))
			end
		end))
		assert.truthy(nb.run())
	end

	it('pipelined exchange DNS over UDP', function ()
		exchange('dgram', nb.udpsend, nb.udprecv, nb.udpxchg, 500)
	end)

	it('pipelined exchange DNS over TCP', function ()
		exchange('stream', nb.tcpsend, nb.tcprecv, nb.tcpxchg, 500)
	end)
end)