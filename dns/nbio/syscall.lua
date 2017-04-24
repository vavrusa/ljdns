local ffi, bit = require('ffi'), require('bit')
local n16 = require('dns.utils').n16

-- We need low-level syscall interface for some calls to avoid expensive conversions
local S, abi = require('syscall'), require('syscall.abi')
local C = require('syscall.' .. abi.os .. '.c')
local c, t = S.c, S.t

-- Consecutive ops limit
local rdops, rdops_max = 0, 256
-- Negotiate buffer sizes
local bufsize_min = 256 * 1024
-- No SIGPIPE on broken connections
S.sigaction('pipe', 'ign')
-- Support MSG_FASTOPEN
if c.TCP.FASTOPEN then c.MSG.FASTOPEN = 0x20000000 end

-- Specialize: do not return source address
-- @note remove when ljdns > 0.12 is used
local function recv(fd, buf, count, flags)
	local ret = C.recvfrom(fd, buf, count or #buf, c.MSG[flags], nil, nil)
	ret = tonumber(ret)
	if ret == -1 then return nil, ffi.errno() end
	return ret
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

local function toaddr(host, port)
	if type(host) == 'cdata' then
		return host
	end
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

return function (M)
local txn = 0
-- Compatibility with OpenResty socket APIs
-- See https://github.com/openresty/lua-nginx-module#ngxsocketudp
--     https://github.com/openresty/lua-nginx-module#ngxsockettcp
M.socket_t = ffi.typeof('struct { int fd; int timeout; }')
ffi.metatype(M.socket_t, {
	__gc = function (self)
		self:close()
	end,
	__index = {
		settimeout = function (self, timeout)
			self.timeout = timeout
		end,
		close = function (self)
			if self.fd > -1 then
				S.close(self.fd)
				self.fd = -1
			end
		end,
		receive = function (self, what, buf, oneshot)
			assert(not what or type(what) == 'number', 'only receive(size?) supported')
			if not what then
				oneshot, what = true, 512
			end
			local copy
			if not buf then
				copy, buf = true, t.buffer(what)
			end
			local rcvd = 0
			local len, err = recv(self.fd, buf, what)
			repeat
				if not len then
					-- Receiving failed, bail out on errors
					if err == c.E.AGAIN then
						coroutine.yield(M.readers, self.fd)
					else
						return nil, tostring(S.t.error(err))
					end
				else
					rcvd = rcvd + len
					if len == 0 or rcvd == what or oneshot then
						break
					end
					coroutine.yield(M.readers, self.fd)
					buf = buf + len
				end
				len = recv(self.fd, buf, what - rcvd)
			until rcvd == what
			-- When buffer is passed, return number of bytes read
			return copy and ffi.string(buf, rcvd) or rcvd
		end,
		receivefrom = function (self, buflen, buf, addr)
			-- Control starvation by limiting number of consecutive read ops
			if rdops > rdops_max then
				rdops = 0
				coroutine.yield(M.readers, self.fd)
			else
				rdops = rdops + 1
			end
			local ret, err, saddr = S.recvfrom(self.fd, buf, buflen, nil, addr)
			if err and err.errno == c.E.AGAIN then
				coroutine.yield(M.readers, self.fd)
				ret, err, saddr = S.recvfrom(self.fd, buf, buflen, nil, addr)
			end
			return ret, err or saddr
		end,
		send = function (self, data, len)
			len = len or #data
			local ret, err = S.send(self.fd, data, len)
			while err and (err.errno == c.E.AGAIN or err.errno == c.E.NOBUFS) do
				coroutine.yield(M.writers, self.fd)
				ret, err = S.send(self.fd, data, len)
			end
			return ret, err
		end,
		sendto = function (self, buf, buflen, addr)
			local ret, err = S.sendto(self.fd, buf, buflen, 0, addr)
			while err and (err.errno == c.E.AGAIN or err.errno == c.E.NOBUFS) do
				coroutine.yield(M.writers, self.fd)
				ret, err = S.sendto(self.fd, buf, buflen, 0, addr)
			end
			return ret, err
		end,
		sendv = function (self, b1, b1len, b2, b2len)
			-- Prepare scatter write
			local iov = ffi.new('struct iovec[2]')
			iov[0].iov_base, iov[0].iov_len = ffi.cast('void *', b1), b1len
			iov[1].iov_base, iov[1].iov_len = ffi.cast('void *', b2), b2len
			local sent, total = 0, b1len + b2len
			-- Bounded maximum number of attempts
			for _ = 1, 3 do
				local nb = C.writev(self.fd, iov, 2)
				-- Connection closed or error
				if not nb or nb <= 0 then
					local err = ffi.errno()
					if err == c.E.AGAIN then
						-- EAGAIN, wait for writeable and retry
						coroutine.yield(M.writers, self.fd)
					else
						return nb, tostring(S.t.error(err))
					end
				else
					sent = sent + nb
					if sent == total then break end
					-- Written less than first buffer, shorten it
					if nb < iov[0].iov_len then
						iov[0].iov_len = iov[0].iov_len - nb
						iov[0].iov_base = ffi.cast('unsigned char *', iov[0].iov_base) + nb
					-- Written less than both buffers, clear first and shorten second
					else
						local off = (nb - iov[0].iov_len)
						iov[1].iov_base = ffi.cast('unsigned char *', iov[1].iov_base) + off
						iov[1].iov_len = iov[1].iov_len - off
						iov[0].iov_len = 0
					end
				end
			end
			return sent
		end,
		connect = function (self, host, port, buf, buflen)
			-- Check if ctype address or (host, port) was passed
			local addr
			if type(host) == 'ctype' then
				addr = host
				buf, buflen = port, buf -- Shift arguments by one
			else
				addr = toaddr(host, port)
			end
			-- Attempt TFO if buffer with data is provided
			if buf then
				buflen = buflen or #buf
				if c.MSG.FASTOPEN then
					local ok, err = S.sendto(self.fd, buf, buflen, c.MSG.FASTOPEN, addr)
					if ok then return ok end
				end
			end
			-- Connect and yield if deferred
			local ok, err = S.connect(self.fd, addr, ffi.sizeof(addr))
			if err and err.errno == c.E.INPROGRESS then
				coroutine.yield(M.writers, self.fd)
				-- Check async connect result
				if S.getsockopt(self.fd, 'socket', 'error') ~= 0 then
					return nil, 'failed to connect'
				end
				ok = true
			end
			if ok and buf then -- Send data after connecting (assume TFO failed)
				return self:send(buf, buflen)
			end
			return ok, err
		end,
		getsockname = function (self)
			local sa = S.getsockname(self.fd)
			return tostring(sa.addr), sa.port
		end,
		getpeername = function (self)
			local sa = S.getpeername(self.fd)
			return tostring(sa.addr), sa.port
		end,
		setpeername = function (self, ...)
			return self:connect(...)
		end,
		accept = function(self)
			coroutine.yield(M.readers, self.fd)
			local fd, err = S.accept(self.fd)
			if not fd then return nil, err end
			fd:nonblock()
			return M.socket_t(fd:nogc():getfd())
		end,
		bind = function (self, host, port, qlen)
			-- Reuse address (if not reusing port)
			S.setsockopt(self.fd, c.SOL.SOCKET, c.SO.REUSEPORT or c.SO.REUSEADDR, true)
			local sa = toaddr(host, port)
			local ok, err = S.bind(self.fd, sa)
			assert(ok, tostring(err))
			-- Guess underlying fd type
			local family = S.getsockopt(self.fd, 'socket', 'type')
			if family == c.SOCK.STREAM then
				-- Support TCP fast open
				if c.TCP.FASTOPEN then
					S.setsockopt(self.fd, c.IPPROTO.TCP, c.TCP.FASTOPEN, 10)
				end
				-- Use deferred accept
				if c.TCP.DEFER_ACCEPT then
					S.setsockopt(self.fd, c.IPPROTO.TCP, c.TCP.DEFER_ACCEPT, true)
				end
				ok, err = S.listen(self.fd, qlen or 64)
				assert(ok, tostring(err))
			end
			-- Negotiate socket buffers for bound sockets to make sure we can get 64K datagrams through
			ok = S.getsockopt(self.fd, c.SOL.SOCKET, c.SO.RCVBUF)
			if ok then S.setsockopt(self.fd, c.SOL.SOCKET, c.SO.RCVBUF, math.max(ok, bufsize_min)) end
			ok = S.getsockopt(self.fd, c.SOL.SOCKET, c.SO.SNDBUF)
			if ok then S.setsockopt(self.fd, c.SOL.SOCKET, c.SO.SNDBUF, math.max(ok, 2*bufsize_min)) end
			return true
		end,
	},
})

-- Create either bound/unbound socket depending
-- on whether the caller provides address
M.addr = t.sockaddr_storage
function M.socket(family, proto)
	assert(family, 'nbio.socket(family[, proto]) expects family = {inet, inet6, unix}')
	proto = proto or 'dgram'
	local sock, err = S.socket(family, proto)
	assert(sock, tostring(err))
	sock:nonblock()
	return M.socket_t(sock:nogc():getfd()), err
end

-- Default clock implementation
if S.mach_absolute_time then
	local tb_info = ffi.new('struct mach_timebase_info')
	assert(ffi.C.mach_timebase_info(tb_info) == 0, 'cannot establish system clock')
	-- Round nanotime to milliseconds first, and then correct to wallclock and normalize
	-- @note early rounding avoids boxing of the 64bit clock value
	local time_correction = tonumber(tb_info.numer / tb_info.denom) * 0.001
	function M.now ()
		return (tonumber(S.mach_absolute_time() / 1000000) * time_correction)
	end
else
	local tv_cached = S.gettimeofday()
	function M.now ()
		S.gettimeofday(tv_cached)
		return tv_cached.time
	end
end

local function nilf()
	return nil
end

-- Create platform-specific poller
-- (Taken from ljsyscall examples)
local poll
if S.epoll_create then
	poll = {
		state = {},
		init = function(p, maxevents)
			p.events = t.epoll_events(maxevents)
			return setmetatable({fd = assert(S.epoll_create())}, {__index = p})
		end,
		event = t.epoll_event(),
		add = function(p, s, write)
			local ev = p.event
			ev.data.fd = s
			-- epoll interface operates on fd, it is not possible to add and remove
			-- separate events, so we need to track what events are currently active on fd
			local ok, err
			local state = p.state[s]
			if state then
				ev.events = bit.bor(state, write and c.EPOLL.OUT or c.EPOLL.IN)
				ok, err = p.fd:epoll_ctl(c.EPOLL_CTL.MOD, s, ev)
			else
				ev.events = write and c.EPOLL.OUT or c.EPOLL.IN
				ok, err = p.fd:epoll_ctl(c.EPOLL_CTL.ADD, s, ev)
			end
			if ok then
				p.state[s] = ev.events
			end
			return ok, err
		end,
		del = function(p, s, write)
			local ev = p.event
			ev.data.fd = s
			-- check currently active events and remove fd from the epollfd only if
			-- there are no more events left after changing the state
			local ok, err
			ev.events = bit.band(p.state[s] or 0, bit.bnot(write and c.EPOLL.OUT or c.EPOLL.IN))
			if ev.events == 0 then
				ok, err = p.fd:epoll_ctl(c.EPOLL_CTL.DEL, s, ev)
				if ok then
					p.state[s] = nil
				end
			else
				ok, err = p.fd:epoll_ctl(c.EPOLL_CTL.MOD, s, ev)
				if ok then
					p.state[s] = ev.events
				end
			end
			return ok, err
		end,
		get = function(p)
			local f, a, r = p.fd:epoll_wait(p.events)
			if not f then
				return nilf
			end
			return f, a, r
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
			local f, a, r = p.fd:kevent(nil, p.events, timeout)
			if not f then
				return nilf
			end
			return f, a, r
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
		eof = function (ev) return bit.band(ev.flags, bit.bor(c.EV.EOF, c.EV.ERROR)) ~= 0 end,
		ein = function (ev) return ev.filter == c.EVFILT.READ end,
		eout = function (ev) return ev.filter == c.EVFILT.WRITE end,
		timer = function (ev) return ev.filter == c.EVFILT.TIMER end,
	}
else
	error('no epoll or kqueue support')
end

-- Coroutines implementation
local pollfd = assert(poll:init(4096))
M.backend = 'syscall'
M.pollfd = pollfd
M.coroutines = 0
M.readers = {}
M.writers = {}

-- Sweep collapsed coroutines from the waitlist
local function sweep(queue)
	local co = table.remove(queue)
	while co and coroutine.status(co) == 'dead' do
		M.coroutines = M.coroutines - 1
		co = table.remove(queue)
	end
	if co then table.insert(queue, co) end
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
		assert(pollfd:add(fd, waitlist == M.writers))
	end
end

-- Remove coroutine from waitlist
local function dequeue(waitlist, fd)
	local queue = waitlist[fd]
	table.remove(queue, 1)
	if not queue[1] then
		pollfd:del(fd, waitlist == M.writers)
	else
		sweep(queue)
	end
end

local function resume(curlist, fd)
	-- Take the coroutine off waitlist
	local co = assert(curlist[fd][1])
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
	-- The coroutine blocked on different fd or for different
	-- action, transfer it to next list and change polling events
	if fd ~= nextfd or curlist ~= nextlist then
		dequeue(curlist, fd)
		enqueue(nextlist, co, nextfd)
	end
	-- Set deadline
	if deadline then
		pollfd:arm(deadline, fd)
	end
	return true
end

function M.go(closure, ...)
	if not closure then return nil end
	-- Coroutine resume transfers ownership to return socket
	local co = coroutine.create(closure)
	local ok, list, fd, deadline = coroutine.resume(co, ...)
	if not ok or not fd then
		return ok, list, co
	end
	enqueue(list, co, fd)
	M.coroutines = M.coroutines + 1
	-- Set deadline
	if deadline then
		pollfd:arm(deadline, fd)
	end
	return co
end

function M.step(timeout)
	local ok, err, co = true, nil, nil
	for _, ev in pollfd:get(timeout) do
		-- Stop listening when error is encountered
		if pollfd.eof(ev) then
			if M.writers[ev.fd] and next(M.writers[ev.fd]) then
				ok, err, co = resume(M.writers, ev.fd)
				M.writers[ev.fd] = nil
			end
			if M.readers[ev.fd] and next(M.readers[ev.fd]) then
				ok, err, co = resume(M.readers, ev.fd)
				M.readers[ev.fd] = nil
			end
		-- Process read/write events
		else
			local list = pollfd.ein(ev) and M.readers or M.writers
			ok, err, co = resume(list, ev.fd)
		end
		if err then break else ok = true end
	end
	return ok, err, co
end

-- Run until there are coroutines to execute
function M.run (timeout)
	local ok, err, co = true
	while ok and M.coroutines > 0 do
		ok, err, co = M.step(timeout)
	end
	return ok, err, co
end

-- DNS/TCP recv
local inflight = {}
function M.tcprecv(sock, msg, pipeline, await_id, leader)
	-- Proceed with the first coroutine in pipeline
	local read_queue = M.readers[sock.fd]
	if pipeline and not leader and read_queue and read_queue[1] then
		-- Do I/O only on first coroutine, it will reorder
		-- waiters after it receives a complete message and resumes this
		local rmsg = coroutine.yield(M.readers, sock.fd)
		-- Either the previous coroutine read an out-of-order response,
		-- or there is no result and it's a continuation
		if rmsg then
			if msg ~= rmsg then
				assert(msg.max_size >= rmsg.size)
				ffi.copy(msg.wire, rmsg.wire, rmsg.size)
				msg.size = rmsg.size
			end
			return msg.size
		end
	end
	-- Receive message length
	local h = ffi.new('uint16_t [1]')
	local ret, err = sock:receive(2, h)
	if ret ~= 2 then
		return nil, err
	end
	-- Decode message length
	local msglen = tonumber(n16(h[0]))
	if msglen < 12 then
		return nil, 'message too short'
	end
	-- Reuse existing buffer, make sure we don't exceed bounds
	assert(msglen <= msg.max_size)
	ret, err = sock:receive(msglen, msg.wire)
	if ret ~= msglen then
		return ret, err
	end
	msg.size = msglen
	if not pipeline then
		return ret
	end
	-- Take waiter off pipeline, its message is reassembled
	assert(type(pipeline) == 'table')
	local id = msg:id()
	local co = pipeline[id]
	pipeline[id] = nil
	-- Received ID is different from awaited, resume different waiter
	-- The resumed coroutine is now nested in current one, and it may block
	-- in that case the parent coroutine must block on the nested one and
	-- retry until the child coroutine finishes or is killed
	if co and id ~= await_id then
		local ok, nextlist, nextfd
		repeat
			ok, nextlist, nextfd = coroutine.resume(co, msg, co)
			if nextfd then
				coroutine.yield(nextlist, nextfd)
			end
		until not ok or not nextfd
		-- Can resume leadership if still on the first position
		return M.tcprecv(sock, msg, pipeline, await_id, true)
	end
	return ret, err
end

-- Specialised DNS/TCP messages stream to support pipelining, reordering and
-- out of order processing. It relies on coroutines support implemented here.
function M.tcpxchg(sock, msg, rmsg, copy)
	local pipeline, id = inflight[sock.fd], msg:id()
	if not pipeline then
		pipeline = {}
		inflight[sock.fd] = pipeline
	end
	-- ID collision, must select different socket
	if pipeline[id] then return false end
	-- Check if there is already a backlog of writers, if so serialise
	local write_queue = M.writers[sock.fd]
	if write_queue and write_queue[1] then
		-- Guarantee immutability while coroutine yields
		if copy then msg = msg:copy() end
		coroutine.yield(M.writers, sock.fd)
	end
	-- Send message and start queueing readers
	-- Only first reader in the queue is woken for I/O and completes
	-- the message reassembly from stream, when it has a complete message
	-- it is either in-order and reader can process it, or it's out-of-order
	-- and reader passes it to appropriate coroutine.
	local ok, err = M.tcpsend(sock, msg)
	if not ok then
		return nil, err
	end
	-- Index coroutines waiting on answer by message ID
	pipeline[id] = coroutine.running()
	-- Receive messages and resume coroutine
	return M.tcprecv(sock, rmsg, pipeline, id)
end

end
