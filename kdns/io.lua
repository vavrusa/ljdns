-- Optional I/O module using LuaSocket
if not pcall(function() require('socket') end) then
	local io = {}
	setmetatable(io, {__index = function (t, k) error('"socket" module missing, no I/O available') end })
	return io
end
local socket = require('socket')
local ffi = require('ffi')
local n16 = require('kdns.utils').n16

-- Return socket connected to peer (UDP or TCP)
local function client (host, port, tcp)
	if port == nil then port = 53 end
	if tcp == nil then tcp = false end
	local sock = false
	if host:find(':', 1, true) ~= nil then
		if tcp then sock = socket.tcp6()
		else        sock = socket.udp6() end
	else
		if tcp then sock = socket.tcp()
		else        sock = socket.udp() end
	end
	if sock then
		sock:settimeout(3)
		sock:setpeername(host, port)
	end
	return sock
end

-- Check if the socket is UDP
local function is_udp(sock) return sock['accept'] == nil end

-- Send DNS message
local msglen_buf = ffi.new('uint16_t [1]')
local function client_send(msg, sock)
	if is_udp(sock) then return sock:send(msg)
	else -- Encode message length for TCP
		local len = n16(#msg)
		msglen_buf[0] = len
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

-- Module interface
local io = {
	client = client,
	send = function (msg, sock) return client_send(msg, sock) end,
	recv = function (sock) return client_recv(sock) end,
	query = function (msg, host, tcp, port)
		local sock = assert(client(host, port, tcp))
		client_send(msg, sock)
		return client_recv(sock)
	end,
	now = socket.gettime,
}
return io