#!/usr/bin/env luajit
local S = require('syscall')
local dns = require('dns')
local warp = require('warp.init')
local go, utils = require('dns.nbio'), require('dns.utils')

-- Support OpenResty modules
_G.require = require('warp.vendor.resty').require

-- Writer closures for UDP and TCP
local function writer_udp(req, msg)
	return go.udpsend(req.sock, msg.wire, msg.size, req.addr)
end
local function writer_tcp(req, msg)
	return go.tcpsend(req.sock, msg.wire, msg.size)
end

-- TCP can pipeline multiple queries in single connection
local function read_tcp(sock, tls)
	local addr, queries, co = sock:getpeername(), 0
	while true do
		local req = warp.request(sock, addr, true)
		-- Read query off socket
		local ok, err = go.tcprecv(sock, req.query.wire, req.query.max_size)
		if ok == 0 then break end
		if not ok then req:log('error', err) break end
		-- Spawn off new coroutine for request
		if queries > 0 then req.sock = sock:dup() end
		req.query.size = ok
		ok, err, co = go(warp.serve, req, writer_tcp)
		if not ok then req:log('error', '%s, %s', err, debug.traceback(co)) end
		queries = queries + 1
	end
	-- Do not wait for GC
	sock:close()
end

-- Bind to sockets and start serving
local function udp(host, port, route)
	-- Create bound sockets
	local msg, addr = string.format('udp "%s#%d: ', host, port), go.addr(host, port)
	local udp, err = go.socket(addr)
	if not udp then error(msg .. err) end
	warp.vlog(nil, msg .. 'listening')
	go(function()
		local addr, ok, err, co = udp:getsockname(), 0
		while ok do
			-- Fetch next request off freelist
			local req = warp.request(udp, addr)
			ok, err = go.udprecv(udp, req.query.wire, req.query.max_size, addr)
			if ok then
				req.query.size = ok
				ok, err, co = go(warp.serve, req, writer_udp, route)
			end
			if err then req:log('error', '%s, %s', err, debug.traceback(co)) end
		end
	end)
end

local function tcp(host, port, route)
	-- Create bound sockets
	local msg, addr = string.format('tcp "%s#%d: ', host, port), go.addr(host, port)
	local tcp, err = go.socket(addr, true)
	if not tcp then error(msg .. err) end
	warp.vlog(nil, msg .. 'listening')
	go(function ()
		local addr, ok, err = tcp:getsockname(), 0
		while ok do
			ok, err = go(read_tcp, go.accept(tcp))
			if err then warp.log({addr=addr}, 'error', tostring(err)) end
		end
	end)
end

local function tls(host, port, route)
	-- Create bound sockets
	local msg, addr = string.format('tls "%s#%d: ', host, port), go.addr(host, port)
	local tcp, err = go.socket(addr, true)
	if not tcp then error(msg .. err) end
	-- Open X.509 credentials and create TLS connection upgrade closure
	local tls = require('dns.tls')
	local cred, err = tls.creds.x509(route.opt)
	if not cred then error(msg .. err) end
	local function read_tls(sock)
		sock = assert(tls.server(sock, cred))
		return read_tcp(sock)
	end
	warp.vlog(nil, msg .. 'listening')
	go(function ()
		local addr, ok, err = tcp:getsockname(), 0
		while ok do
			ok, err = go(read_tls, go.accept(tcp))
			if err then warp.log({addr=addr}, 'error', tostring(err)) end
		end
	end)
end

-- Listen on HTTP for metrics
local prometheus = require('warp.route.prometheus').init()

local function write_http(req, msg, ctype)
	ctype = ctype or 'application/json'
	local tpl = 'HTTP/1.0 200 OK\nContent-Length: %d\nContent-Type: %s\n\n%s'
	req.sock:send(tpl:format(#msg, ctype, msg))
end

local function read_http(sock)
	local addr = sock:getpeername()
	local ok, err = pcall(prometheus.serve, prometheus, {sock=sock}, write_http)
	if not ok then warp.log(nil, 'error', err) end
	sock:close()
end

local function http(host, port)
	local msg, addr = string.format('interface "%s#%d: ', host, port), go.addr(host, port)
	local tcp, err = go.socket(addr, true)
	if not tcp then error(msg..err) end
	warp.vlog(nil, msg .. 'serving metrics')
	go(function ()
		local addr, ok, err = tcp:getsockname(), 0
		while ok do
			ok, err = go(read_http, go.accept(tcp))
			if err then warp.log({addr=addr}, 'error', tostring(err)) end
		end
	end)
end

local function help()
	print(string.format('Usage: %s [options] <config>', arg[0]))
	print('Options:')
	print('\t-h,--help        ... print this help')
	print('\t-v               ... verbose logging')
	print('\t-m <addr>[#port] ... serve metrics on address/port (e.g. ::1#8080)')
end

-- Parse arguments and start serving
local k = 1 while k <= #arg do
	local v = arg[k]
	local chr = string.char(v:byte())
	if k < 1 then break
	elseif v == '-v' then
		warp.vlog = function (req, ...) return warp.log(req, 'info', ...) end
	elseif v == '-h' or v == '--help' then
		help()
		return 0
	elseif v == '-m' then
		v, k = arg[k + 1], k + 1
		http(v:match '([^#]+)', tonumber(v:match '#(%d+)$') or 8080)
	else
		warp.conf(v)
	end
	k = k + 1
end
-- Serve configured interfaces
for _,iface in ipairs(warp.hosts) do
	if iface.scheme == 'dns' then
		udp(iface.host, iface.port, iface)
		tcp(iface.host, iface.port, iface)
	elseif iface.scheme == 'tls' then
		tls(iface.host, iface.port, iface)
	else
		error('unknown downstream scheme: ' .. iface.scheme)
	end
end

-- Enable trace stitching
require('jit.opt').start('minstitch=2')
-- Limit the number of in-flight requests
go.concurrency(100)
-- Run coroutines
while true do
	local ok, err, co = go.run(1)
	if not ok then
		warp.log(nil, 'error', '%s, %s', err, debug.traceback(co))
	end
end
