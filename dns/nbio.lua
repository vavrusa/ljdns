-- Asynchronous I/O with scoped coroutines
--
-- It works like this:
-- 1. a coroutine is spawned in current scope, it may start any asynchronous operation
-- 2. if the socket blocks, coroutine yields a waitlist (and a socket) on which it blocked
-- 3. the coroutine ownership is transferred to that socket and waits
-- 4. the coroutine is resumed (2) with that event or collapsed if the socket is closed
--
-- The module itself holds tables of readers and writers and poller backend (platform specific)
--
-- Note: if a coroutine collapses, it also collapses its child coroutines. This is basically
--       a structured concurrency as in http://250bpm.com/blog:71 without grace periods.

local ffi, bit = require('ffi'), require('bit')
local n16 = require('dns.utils').n16

-- Declare module
local M = {
	coroutines = 0,
	readers = {},
	writers = {},
}

local nbsend, nbsendv, nbrecv, nbsendto, nbrecvfrom
local rcvbuf = ffi.new('char [?]', 4096)
local inflight = {}

-- DNS/TCP send
local function tcpsend(sock, msg, msglen)
	if not msglen then msglen = #msg end
	local rcvlenbuf = ffi.new('uint16_t [1]')
	rcvlenbuf[0] = n16(tonumber(msglen))
	local ok, err = nbsendv(sock, rcvlenbuf, 2, msg, msglen)
	return ok, err and tostring(err)
end

-- DNS/TCP recv
local function tcprecv(sock, buf, buflen, pipeline, await_id)
	-- Proceed with the first coroutine in pipeline
	if pipeline and pipeline.c > 1 then
		-- Do I/O only on first coroutine, it will reorder
		-- waiters after it receives a complete message and resumes this
		local ret, err, rbuf = coroutine.yield(M.readers, sock)
		-- Either the previous coroutine read an out-of-order response,
		-- or there is no result and it's a continuation
		if ret then
			if ret > 0 then
				ffi.copy(buf, rbuf, ret)
			end
			return ret, err
		end
	end
	local rcvlenbuf = ffi.new('uint16_t [1]')
	local ret, err = nbrecv(sock, rcvlenbuf, 2)
	if ret == 2 then -- Decode message length
		ret = n16(rcvlenbuf[0])
		-- Receive into new buffer
		if not buf then
			buf = ffi.new('char [?]', ret)
			local rcvd = nbrecv(sock, buf, ret)
			ret = ffi.string(buf, rcvd)
		else -- Reuse existing buffer, make sure we don't exceed bounds
			assert(ret <= buflen)
			ret, err = nbrecv(sock, buf, ret)
		end
		-- Reorder coroutines waiting for this query
		if pipeline then
			local id = ffi.cast('uint16_t *', buf)
			id = (ret > 1) and n16(id[0]) or -1
			-- Take waiter off pipeline, its message is reassembled
			local co = pipeline.q[id]
			if co then
				pipeline.c = pipeline.c - 1
				pipeline.q[id] = nil
			end
			-- Received ID is different from awaited, resume different waiter
			-- The resumed coroutine is now nested in current one, and it may block
			-- in that case the parent coroutine must block on the nested one and
			-- retry until the child coroutine finishes or is killed
			if co and id ~= await_id then
				-- Bounded maximum number of attempts
				for _ = 1, 10 do
					local ok, nextlist, nextfd = coroutine.resume(co, ret, err, buf)
					if ok and nextfd then
						coroutine.yield(nextlist, nextfd)
					else
						break
					end
				end
				return tcprecv(sock, buf, buflen, pipeline, await_id)
			end
		end
	end
	return ret, err
end

local function tcpxchg(sock, msg, rmsg)
	-- Pipeline DNS/TCP messages in connection, this implements pipelining
	-- and message reordering on single stream
	local pipeline, id = inflight[sock], msg:id()
	if not pipeline then
		pipeline = {c=0,q={}}
		inflight[sock] = pipeline
	end
	-- ID collision, must select different socket
	if pipeline.q[id] then return false end
	-- Send message and start queueing readers
	-- Only first reader in the queue is woken for I/O and completes
	-- the message reassembly from stream, when it has a complete message
	-- it is either in-order and reader can process it, or it's out-of-order
	-- and reader passes it to appropriate coroutine.
	local ok, err = tcpsend(sock, msg.wire, msg.size)
	if not ok then
		return nil, err
	end
	-- Index coroutines waiting on answer by message ID
	pipeline.c = pipeline.c + 1
	pipeline.q[id] = coroutine.running()
	-- Receive messages and resume coroutine
	ok, err = tcprecv(sock, rmsg.wire, rmsg.max_size, pipeline, id)
	return ok, err
end

local function udpsend(sock, msg, msglen, addr)
	if not msglen then msglen = #msg end
	return addr and nbsendto(sock, addr, msg, msglen) or nbsend(sock, msg, msglen)
end

local function udprecv(sock, buf, buflen, addr)
	local ret, err
	-- Receive into new buffer
	if not buf then
		ret, err, addr = nbrecvfrom(sock, addr, rcvbuf, ffi.sizeof(rcvbuf))
		if ret then ret = ffi.string(rcvbuf, ret) end
		return ret, err, addr
	-- Receive on "connected" UDP socket
	elseif not addr then
		return nbrecv(sock, buf, buflen, true)
	end
	-- Reuse existing buffer, make sure we don't exceed bounds
	return nbrecvfrom(sock, addr, buf, buflen)
end

local function sockfamily(addr)
	if addr:find('/', 1, true) then
		return 'unix'
	end
	if addr:find(':', 1, true) then
		return 'inet6'
	end
	return 'inet'
end

-- Send pair (default behaviour)
local function nbsendv_compat(sock, b1, b1len, b2, b2len)
	local ok, err = nbsend(sock, b1, b1len)
	if ok == b1len then
		ok, err = nbsend(sock, b2, b2len)
	end
	return ok, err
end
nbsendv = nbsendv_compat

-- Export basic I/O interface
M.tcpsend, M.tcprecv, M.tcpxchg = tcpsend, tcprecv, tcpxchg
M.udpsend, M.udprecv = udpsend, udprecv
M.family = sockfamily

-- NGINX implementation
if ngx then
	M.backend = 'nginx'
	M.socket = function (addr, tcp, client)
		return tcp and ngx.socket.tcp() or ngx.socket.udp()
	end
	M.connect = function (sock, host, port)
		return sock:connect(host, port)
	end
	nbsend = function (sock, buf, len)
		return sock:send(ffi.string(buf, len))
	end
	nbrecv = function (sock, buf, len)
		local ret, err = sock:receive()
		if not ret then return nil, err end
		if buf and len then
			local n = #ret
			assert(len >= n)
			ffi.copy(buf, ret, n)
			return n
		end
		return ret
	end
end

-- ljsyscall implementation
if not pcall(function() require('syscall') end) then
	return setmetatable(M, {__index = function (t, k)
		error('"syscall" module missing, no I/O available')
	end})
end
local S = require('syscall')
local c, t = S.c, S.t

local function recv(fd, buf, count, flags)
	if ffi.istype(S.t.fd, fd) then
		-- Specialize: do not return source address
		-- @note remove when ljdns > 0.12 is used
		local ret, err = ffi.C.recvfrom(fd:getfd(), buf, count or #buf, c.MSG[flags], nil, nil)
		ret = tonumber(ret)
		if ret == -1 then return nil, ffi.errno() end
		return ret
	else
		return fd:recv(buf, count, flags)
	end
end

-- Default clock implementation
local gettime
if S.mach_absolute_time then
	local time_correction
	do
		local tb_info = ffi.new('struct mach_timebase_info')
		assert(ffi.C.mach_timebase_info(tb_info) == 0, 'cannot establish system clock')
		-- Round nanotime to milliseconds first, and then correct to wallclock and normalize
		-- @note early rounding avoids boxing of the 64bit clock value
		time_correction = tonumber(tb_info.numer / tb_info.denom) * 0.001
	end
	gettime = function ()
		return (tonumber(S.mach_absolute_time() / 1000000) * time_correction)
	end
else
	local tv_cached = S.gettimeofday()
	gettime = function()
		S.gettimeofday(tv_cached)
		return tv_cached.time
	end
end

-- Consecutive ops limit
local rdops, rdops_max = 0, 256
-- Negotiate buffer sizes
local bufsize_min = 128 * 1024
-- No SIGPIPE on broken connections
S.sigaction('pipe', 'ign')
-- Support MSG_FASTOPEN
if c.TCP.FASTOPEN then c.MSG.FASTOPEN = 0x20000000 end

-- Create platform-specific poller
-- (Taken from ljsyscall examples)
local poll = nil
if S.epoll_create then
	poll = {
		init = function(p, maxevents)
			p.events = t.epoll_events(maxevents)
			return setmetatable({fd = assert(S.epoll_create())}, {__index = p})
		end,
		event = t.epoll_event(),
		add = function(p, s, write)
			local ev = p.event
			ev.events = write and c.EPOLL.OUT or c.EPOLL.IN
			ev.data.fd = s
			return p.fd:epoll_ctl(c.EPOLL_CTL.ADD, s, ev)
		end,
		del = function(p, s, write)
			local ev = p.event
			ev.events = write and c.EPOLL.OUT or c.EPOLL.IN
			ev.data.fd = s
			return p.fd:epoll_ctl(c.EPOLL_CTL.DEL, s, ev)
		end,
		get = function(p)
			return p.fd:epoll_wait(p.events)
		end,
		eof = function(ev) return ev.HUP or ev.ERR or ev.RDHUP end,
		ein = function(ev) return bit.band(ev.events, c.EPOLL.IN) ~= 0 end,
		eout = function(ev) return bit.band(ev.events, c.EPOLL.OUT) ~= 0 end,
		timer = function(ev) return false end, -- NYI
	}
elseif S.kqueue then
	poll = {
		init = function(p, maxevents)
			p.events = t.kevents(maxevents)
			return setmetatable({fd = assert(S.kqueue())}, {__index = p})
		end,
		event = t.kevents(1),
		add = function(p, s, write)
			local ev = p.event.kev[0]
			ev.fd = s
			ev.setfilter = write and c.EVFILT.WRITE or c.EVFILT.READ
			ev.setflags = c.EV.ADD
			return p.fd:kevent(p.event, nil)
		end,
		del = function (p, s, write)
			local ev = p.event.kev[0]
			ev.fd = s
			ev.setfilter = write and c.EVFILT.WRITE or c.EVFILT.READ
			ev.setflags = c.EV.DELETE
			return p.fd:kevent(p.event, nil)
		end,
		get = function(p, timeout)
			return p.fd:kevent(nil, p.events, timeout)
		end,
		arm = function (p, timeout, fd)
			local ev = p.event.kev[0]
			ev.signal = 0
			ev.fd = fd or 0
			ev.setfilter = c.EVFILT.TIMER
			ev.setflags = c.EV.ADD + c.EV.ONESHOT
			ev.data = timeout
			return p.fd:kevent(p.event, nil)
		end,
		eof = function(ev) return ev.EOF or ev.ERROR end,
		ein = function(ev) return ev.filter == c.EVFILT.READ end,
		eout = function(ev) return ev.filter == c.EVFILT.WRITE end,
		timer = function(ev) return ev.filter == c.EVFILT.TIMER end,
	}
else
	error('no epoll or kqueue support')
end

-- Module interface
M.backend = 'ljsyscall'
M.pollfd = poll:init(512)

-- Create socket address
local function getaddr(host, port)
	local family = sockfamily(host, port)
	if not port then
		if family == 'unix' then
			return t.sockaddr_un(host)
		end
		port = 53
	end
	local socktype = (family == 'inet6') and t.sockaddr_in6 or t.sockaddr_in
	return socktype(port, host)
end

-- Create either bound/unbound socket depending
-- on whether the caller provides address
local function getsocket(addr, tcp, client)
	-- Get either address type or family name
	local family
	if type(addr) ~= 'cdata' then
		family, addr = addr, nil
	else
		family = addr.family
	end
	local proto = tcp and c.SOCK.STREAM or c.SOCK.DGRAM
	local sock, err = S.socket(family, proto)
	assert(sock, tostring(err))
	-- Bind (or listen) on socket if address provided
	if addr and not client then
		-- Reuse address (if not reusing port)
		sock:setsockopt(c.SOL.SOCKET, c.SO.REUSEPORT or c.SO.REUSEADDR, true)
		local ok, err = sock:bind(addr)
		assert(ok, tostring(err))
		if tcp then
			-- Support TCP fast open
			if c.TCP.FASTOPEN then
				sock:setsockopt(c.IPPROTO.TCP, c.TCP.FASTOPEN, 10)
			end
			-- Use deferred accept
			if c.TCP.DEFER_ACCEPT then
				sock:setsockopt(c.IPPROTO.TCP, c.TCP.DEFER_ACCEPT, true)
			end
			ok, err = sock:listen(64)
			assert(ok, tostring(err))
		end
		-- Negotiate socket buffers for bound sockets to make sure we can get 64K datagrams through
		ok = sock:getsockopt(c.SOL.SOCKET, c.SO.RCVBUF)
		if ok then sock:setsockopt(c.SOL.SOCKET, c.SO.RCVBUF, math.max(ok, bufsize_min)) end
		ok = sock:getsockopt(c.SOL.SOCKET, c.SO.SNDBUF)
		if ok then sock:setsockopt(c.SOL.SOCKET, c.SO.SNDBUF, math.max(ok, 4*bufsize_min)) end
	end
	sock:nonblock()
	return sock, err
end

-- Receive bytes from stream (with yielding when not ready)
nbrecv = function(sock, buf, buflen, short)
	if buflen == 0 then return 0 end
	short = short or not buflen
	if not buf then
		buf, buflen = rcvbuf, ffi.sizeof(rcvbuf)
	end
	local rcvd = 0
	local len, err = recv(sock, buf, buflen)
	repeat
		if not len then
			-- Receiving failed, bail out on errors
			if err == c.E.AGAIN then
				coroutine.yield(M.readers, sock)
			else
				return nil, err
			end
		else
			rcvd = rcvd + len
			if len == 0 or rcvd == buflen or short then
				break
			end
			coroutine.yield(M.readers, sock)
			buf = buf + len
		end
		len = recv(sock, buf, buflen - rcvd)
	until rcvd == buflen
	return rcvd, buf
end

-- Send bytes to stream (with yielding when not ready)
nbsend = function(sock, buf, buflen)
	local ret, err = sock:send(buf, buflen)
	if not ret and err.errno == c.E.AGAIN then
		coroutine.yield(M.writers, sock)
		ret, err = sock:send(buf, buflen)
	end
	return ret, err
end

-- Send buffer pair with scatter/gather write
nbsendv = function(sock, b1, b1len, b2, b2len)
	-- Use specialised version only for ljsyscall sockets
	if not ffi.istype(S.t.fd, sock) then
		return nbsendv_compat(sock, b1, b1len, b2, b2len)
	end
	-- Prepare scatter write
	local iov = ffi.new('struct iovec[2]')
	iov[0].iov_base, iov[0].iov_len = ffi.cast('void *', b1), b1len
	iov[1].iov_base, iov[1].iov_len = ffi.cast('void *', b2), b2len
	local sent, total = 0, b1len + b2len
	-- Bounded maximum number of attempts
	for _ = 1, 10 do
		local nb = ffi.C.writev(sock:getfd(), iov, 2)
		-- Connection closed or error
		if not nb or nb <= 0 then
			local err = ffi.errno()
			if err == c.E.AGAIN then
				-- EAGAIN, wait for writeable and retry
				coroutine.yield(M.writers, sock)
			else
				return nb, err
			end
		else
			sent = sent + nb
			if sent == total then break end
			-- Written less than first buffer, shorten it
			if nb < iov[0].iov_len then
				iov[0].iov_len = iov[0].iov_len - nb
				iov[0].iov_base = iov[0].iov_base + nb
			-- Written less than both buffers, clear first and shorten second
			else 
				local off = (nb - iov[0].iov_len)
				iov[1].iov_base = iov[1].iov_base + off
				iov[1].iov_len = iov[1].iov_len - off
				iov[0].iov_len = 0
			end
		end
	end
	return sent
end

-- Receive datagrams (with yielding when not ready)
nbrecvfrom = function(sock, addr, buf, buflen)
	-- Control starvation by limiting number of consecutive read ops
	rdops = rdops + 1
	if rdops > rdops_max then
		coroutine.yield(M.readers, sock)
		rdops = 0
	end
	local ret, err, saddr = sock:recvfrom(buf, buflen, nil, addr)
	if err and err.errno == c.E.AGAIN then
		coroutine.yield(M.readers, sock)
		ret, err, saddr = sock:recvfrom(buf, buflen, nil, addr)
	end
	return ret, err or saddr
end

-- Send datagrams (with yielding when not ready)
nbsendto = function(sock, addr, buf, buflen)
	local ret, err = sock:sendto(buf, buflen, 0, addr)
	if not ret and err.errno == c.E.AGAIN then
		coroutine.yield(M.writers, sock)
		ret, err = sock:sendto(buf, buflen, 0, addr)
	end
	return ret, err
end

-- Wrapper for asynchronous I/O
local function connect(sock, addr, buf, buflen)
	if type(addr) == 'string' then
		addr, buf = getaddr(addr, buf), nil
	end
	local packed_msg = nil
	if buf and addr and c.MSG.FASTOPEN then
		-- Need to serialize data for first message (no writev support)
		if not buflen then buflen = #buf end
		packed_msg = ffi.new('uint8_t [?]', buflen + 2)
		local txlen = ffi.cast('uint16_t *', packed_msg)
		txlen[0] = n16(tonumber(buflen))
		ffi.copy(packed_msg + 2, buf, buflen)
		-- Attempt TCP Fast Open (fallback if fails)
		local ok, err = sock:sendto(packed_msg, buflen + 2, c.MSG.FASTOPEN, addr)
		if ok then return ok end
	end
	local ok, err = sock:connect(addr)
	if err and err.errno == c.E.INPROGRESS then
		coroutine.yield(M.writers, sock)
		-- Check asynchornous connect result
		if sock:getsockopt('socket', 'error') ~= 0 then
			return nil, 'failed to connect'
		end
	end
	if buf then -- Send data after connecting (assume TFO failed)
		if packed_msg then -- Reuse already serialized message
			return nbsend(sock, packed_msg, buflen + 2)
		else
			return tcpsend(sock, buf, buflen)
		end
	end
	return true
end

local function accept(sock)
	assert(sock)
	coroutine.yield(M.readers, sock)
	return sock:accept('nonblock')
end

local function block(sock, timeout)
	assert(sock)
	coroutine.yield(M.readers, sock, timeout)
end

-- Transfer ownerwhip to a different waitlist
local function enqueue(waitlist, co, fd)
	if not waitlist then waitlist = M.readers end
	local queue = waitlist[fd]
	if not queue then
		waitlist[fd] = {co}
	else
		table.insert(queue, co)
	end
	if fd > -1 then
		assert(M.pollfd:add(fd, waitlist == M.writers))
	end
end

local function dequeue(waitlist, fd)
	local queue = waitlist[fd]
	local co = table.remove(queue, 1)
	if not next(queue) then
		M.pollfd:del(fd, waitlist == M.writers)
	end
	return co
end

local function resume(curlist, fd)
	-- Take the coroutine off waitlist
	local _, co = next(curlist[fd])
	assert(co)
	-- Resume coroutine, check when it's finished
	if coroutine.status(co) == 'dead' then
		dequeue(curlist, fd)
		M.coroutines = M.coroutines - 1
		return resume(curlist, fd)
	end
	local ok, nextlist, nextfd, deadline = coroutine.resume(co)
	if not ok or not nextfd then
		M.coroutines = M.coroutines - 1
		dequeue(curlist, fd)
		return false, nextlist, co
	end
	if type(nextfd) ~= 'number' then
		nextfd = nextfd:getfd()
	end
	-- The coroutine blocked on different fd or for different
	-- action, transfer it to next list and change polling events
	if fd ~= nextfd or curlist ~= nextlist then
		dequeue(curlist, fd)
		enqueue(nextlist, co, nextfd)
	end
	-- Set deadline
	if deadline then
		M.pollfd:arm(deadline, fd)
	end
	return true
end

local function start(closure, ...)
	if not closure then return nil end
	-- If maximum number of coroutines is reached, execute in parent
	if M.max_coroutines and M.coroutines >= M.max_coroutines then
		return pcall(closure, ...)
	end
	-- Coroutine resume transfers ownership to return socket
	local co = coroutine.create(closure)
	local ok, list, fd, deadline = coroutine.resume(co, ...)
	if not ok or not fd then
		return ok, list, co
	end
	if type(fd) ~= 'number' then
		fd = fd:getfd()
	end
	enqueue(list, co, fd)
	M.coroutines = M.coroutines + 1
	-- Set deadline
	if deadline then
		M.pollfd:arm(deadline, fd)
	end
	return co
end

local function step(timeout)
	local pollfd, ok, err, co, count = M.pollfd, true, nil, nil, 0
	for _, ev in pollfd:get(timeout) do
		-- Stop listening when error is encountered
		if pollfd.eof(ev) then
			if M.writers[ev.fd] then
				ok, err, co = resume(M.writers, ev.fd)
				M.writers[ev.fd] = nil
			end
			if M.readers[ev.fd] then
				ok, err, co = resume(M.readers, ev.fd)
				M.writers[ev.fd] = nil
			end
		-- Process write events
		elseif pollfd.eout(ev) then
			count = count + 1
			ok, err, co = resume(M.writers, ev.fd)
		-- Process read events
		elseif pollfd.ein(ev) or pollfd.timer(ev) then
			count = count + 1
			ok, err, co = resume(M.readers, ev.fd)
		end
		if err then break else ok = true end
	end
	return ok, err, co
end

-- Compose module interface
M.addr = function (host, port) return getaddr(host, port) end
M.socket = getsocket
M.now = gettime
M.go  = start
M.step, M.block = step, block
M.nbsend, M.nbrecv = nbsend, nbrecv
M.connect = connect
M.accept = accept

-- Run until there are coroutines to execute
M.run = function (timeout)
	local ok, err, co = true
	while ok and M.coroutines > 0 do
		ok, err, co = step(timeout)
	end
	return ok, err, co
end

-- Set maximum concurrency
function M.concurrency(c)
	M.max_coroutines = c
end

return setmetatable(M, {
	__call = function(c, closure, ...) return start(closure, ...) end,
})
