-- This module implements interface for sending and receiving DNS messages
local ffi = require('ffi')
local n16 = require('dns.utils').n16

-- Declare module
local M = {}

function M.family(addr)
	if addr:find('/', 1, true) then
		return 'unix'
	end
	if addr:find(':', 1, true) then
		return 'inet6'
	end
	return 'inet'
end

function M.udpsend(sock, msg, addr)
	if addr then
		return sock:sendto(msg.wire, msg.size, addr)
	end
	return sock:send(msg.wire, msg.size)
end

function M.udprecv(sock, msg, addr)
	-- Receive on "connected" UDP socket
	local n, err
	if not addr then
		n, err = sock:receive(tonumber(msg.max_size), msg.wire, true)
	else
		-- Reuse existing buffer, make sure we don't exceed bounds
		n, err = sock:receivefrom(tonumber(msg.max_size), msg.wire, addr)
	end
	if not n then return nil, err end
	if type(n) == 'number' then
		msg.size = n
	end
	return n
end

-- Send buffer pair (default behaviour)
local function sendv_compat(sock, b1, b1len, b2, b2len)
	local ok, err = sock:send(b1, b1len)
	if ok == b1len then
		ok, err = sock:send(b2, b2len)
	end
	return ok, err
end

-- DNS/TCP send
function M.tcpsend(sock, msg)
	local h = ffi.new('uint16_t [1]')
	h[0] = n16(tonumber(msg.size))
	local ok, err
	if sock.sendv then
		ok, err = sock:sendv(h, 2, msg.wire, msg.size)
		if ok then ok = ok - 2 end -- Subtract header len
	else
		ok, err = sendv_compat(sock, h, 2, msg.wire, msg.size)
	end
	return ok, err
end

-- DNS/TCP recv
function M.tcprecv(sock, msg, pipeline, await_id, leader)
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
	return ret
end

function M.udpxchg(sock, msg, rmsg)
	local ok, err = M.udpsend(sock, msg)
	if not ok then return nil, err end
	return M.udprecv(sock, rmsg)
end

function M.tcpxchg(sock, msg, rmsg)
	local ok, err = M.tcpsend(sock, msg)
	if not ok then return nil, err end
	return M.tcprecv(sock, rmsg)
end

-- Select backend implementation
-- Each backend implements at least socket(), go(), now()
if ngx then
	require('dns.nbio.openresty')(M)
elseif pcall(require, 'syscall') then
	require('dns.nbio.syscall')(M)
else
	error('no backend I/O available')
end

-- Call metamethod implements coroutine start
return setmetatable(M, {
	__call = function(c, closure, ...) return M.go(closure, ...) end,
})
