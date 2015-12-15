-- Optional I/O module using LuaSocket
if not pcall(function() require('socket') end) then
	local io = {}
	setmetatable(io, {__index = function (t, k) error('"socket" module missing, no I/O available') end })
	return io
end
local socket = require('socket')
local ffi = require('ffi')
local n16 = require('kdns.utils').n16
local poll = socket.select

-- Return appropriate socket implementation
local function getsocket(addr, tcp)
	if addr:find(':', 1, true) ~= nil then
		if tcp then return socket.tcp6()
		else        return socket.udp6() end
	else
		if tcp then return socket.tcp()
		else        return socket.udp() end
	end
	return false
end

-- Return socket connected to peer (UDP or TCP)
local function client (host, port, tcp)
	if port == nil then port = 53 end
	local sock = getsocket(host, tcp)
	if sock then
		sock:settimeout(3)
		sock:setpeername(host, port)
	end
	return sock
end

-- Return bound / listening socket (UDP or TCP)
local function server (addr, port, tcp)
	if port == nil then port = 53 end
	local sock = false
	if tcp then
		sock = socket.bind(addr, port)
	else
		sock = getsocket(addr)
		local ok, err = sock:setsockname(addr, port)
		if not ok then return false, err end
	end
	if sock then
		sock:settimeout(0) -- Non-blocking
	end
	return sock
end

-- Check if the socket is UDP
local function is_udp(sock) return sock['accept'] == nil end

-- Send DNS message
local msglen_buf = ffi.new('uint16_t [1]')
local function client_send(sock, msg, len)
	if is_udp(sock) then return sock:send(msg)
	else -- Encode message length for TCP
		if not len then len = #msg end
		msglen_buf[0] = n16(len)
		sock:send(ffi.string(msglen_buf, 2))
		return sock:send(msg)
	end
end

-- Receive DNS message
local function client_recv(sock)
	if is_udp(sock) then return sock:receive()
	else -- Decode DNS message length for TCP
		local len = sock:receive(2)
		local ret = nil
		if len ~= nil then
			ffi.copy(msglen_buf, len, 2)
			len = n16(msglen_buf[0])
			ret = sock:receive(len)
		end
		return ret
	end
end

-- Asynchronous I/O callbacks
local function async_write(socket, msg, len)
	table.insert(writers, socket)
	coroutine.yield()
	client_send(socket, msg, len)
end
local function async_recv(socket)
	coroutine.yield()
	return client_recv(socket)
end
local function async_remove(sockets, reverse, pending, s)
	table.remove(sockets, reverse[s])
	reverse[s] = nil
	pending[s] = nil
	s:close()
end
local function async_add(sockets, reverse, pending, s)
	reverse[s] = #sockets + 1
	pending[s] = co
	table.insert(sockets, s)
end
local function async_resume(sockets, reverse, pending, s)
	local ok = coroutine.resume(pending[s])
	if not ok or coroutine.status(pending[s]) == 'dead' then
		async_remove(sockets, reverse, pending, s)
		return false
	end
	return true
end

local function asio_init(sockets)
	-- Prepare socket set and reverse mapping
	local reverse, listeners, writers, pending = {}, {}, {}, {}
	local context = { writers }
	for i, s in ipairs(sockets) do listeners[s] = true end
	-- Return closure with asynchronous I/O step
	return function (timeout)
		-- Poll active sockets
		local readable, writeable = poll(sockets, writers, timeout)
		writers = {}
		-- Process all readable
		for i, s in ipairs(readable) do
			if listeners[s] then
				local client = s:accept()
				local co = coroutine.create(on_recv)
				co:resume(context, client)
				if coroutine.status(co) ~= 'dead' then
					async_add(sockets, reverse, pending, client)
				else
					client:close()
				end
			else async_resume(sockets, reverse, pending, s) end
		end
		-- Process all writeable
		for i, s in ipairs(writeable) do
			async_resume(sockets, reverse, pending, s)
		end
		return true
	end
end

-- Module interface
local io = {
	server = server,
	client = client,
	poll = socket.select,
	send = function (sock, msg, len) return client_send(sock, msg, len) end,
	recv = function (sock) return client_recv(sock) end,
	query = function (msg, host, tcp, port)
		local sock = assert(client(host, port, tcp))
		client_send(sock, msg)
		return client_recv(sock)
	end,
	now = socket.gettime,
}
return io