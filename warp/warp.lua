#!/usr/bin/env luajit
local S = require('syscall')
local dns = require('dns')
local warp = require('warp.init')
local go, utils = require('dns.nbio'), require('dns.utils')

-- Support OpenResty modules
_G.require = require('warp.vendor.resty').require
-- Enable trace stitching
require('jit.opt').start('minstitch=2')
-- Limit the number of in-flight requests
go.concurrency(256)

-- Writer closures for UDP and TCP
local function writer_udp(req, msg)
	return go.udpsend(req.sock, msg.wire, msg.size, req.addr)
end
local function writer_tcp(req, msg)
	return go.tcpsend(req.sock, msg.wire, msg.size)
end

-- TCP can pipeline multiple queries in single connection
local function read_tcp(sock, routemap)
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
		ok, err, co = go(warp.serve, req, writer_tcp, routemap)
		if not ok then req:log('error', '%s, %s', err, debug.traceback(co)) end
		queries = queries + 1
	end
	-- Do not wait for GC
	sock:close()
end

-- Bind to sockets and start serving
local function udp(host, port, iface)
	-- Create bound sockets
	local msg, addr = string.format('udp "%s#%d: ', host, port), go.addr(host, port)
	local sock, err = go.socket(addr)
	if not sock then error(msg .. err) end
	warp.vlog(nil, msg .. 'listening')
	local addr, ok, err, co = sock:getsockname(), 0
	for _ = 1, go.max_coroutines/4 do
		go(function()
			while ok do
				-- Fetch next request off freelist
				local req = warp.request(sock, addr)
				ok, err = go.udprecv(sock, req.query.wire, req.query.max_size, addr)
				if ok then
					req.query.size = ok
					ok, err, co = pcall(warp.serve, req, writer_udp, iface.match)
				end
				if err then req:log('error', '%s, %s', err, debug.traceback(co)) end
			end
		end)
	end
end

local function tcp(host, port, iface)
	-- Create bound sockets
	local msg, addr = string.format('tcp "%s#%d: ', host, port), go.addr(host, port)
	local tcp, err = go.socket(addr, true)
	if not tcp then error(msg .. err) end
	warp.vlog(nil, msg .. 'listening')
	go(function ()
		local addr, ok, err = tcp:getsockname(), 0
		while ok do
			ok, err = go(read_tcp, go.accept(tcp), iface.match)
			if err then warp.log({addr=addr}, 'error', tostring(err)) end
		end
	end)
end

local function tls(host, port, iface)
	-- Create bound sockets
	local msg, addr = string.format('tls "%s#%d: ', host, port), go.addr(host, port)
	local tcp, err = go.socket(addr, true)
	if not tcp then error(msg .. err) end
	-- Open X.509 credentials and create TLS connection upgrade closure
	local tls = require('dns.tls')
	local cred, err = tls.creds.x509(iface.opt)
	if not cred then error(msg .. err) end
	local function read_tls(sock, routemap)
		sock = assert(tls.server(sock, cred))
		return read_tcp(sock, routemap)
	end
	warp.vlog(nil, msg .. 'listening')
	go(function ()
		local addr, ok, err = tcp:getsockname(), 0
		while ok do
			ok, err = go(read_tls, go.accept(tcp), iface.match)
			if err then warp.log({addr=addr}, 'error', tostring(err)) end
		end
	end)
end

local function write_http(req, msg, code, ctype)
	ctype = ctype or 'application/json'
	code = code or '200 OK'
	local tpl = 'HTTP/1.0 %s\nContent-Length: %d\nContent-Type: %s\n\n%s'
	req.sock:send(tpl:format(code, #msg, ctype, msg))
end

local function read_http(sock, req, route)
	local addr = sock:getpeername()
	req.sock, req.addr = sock, addr
	-- TODO: worry about partial header reads
	local headers = req.sock:read()
	if headers then
		req.method, req.url, req.proto = headers:match('(%S+)%s(%S+)%s([^\n]+)')
		-- Serve API call
		local ok, err = pcall(warp.api, req, write_http, route)
		if not ok then warp.log({addr=addr}, 'error', err) end
	end
	sock:close()
end

local function http(host, port, iface)
	local msg, addr = string.format('interface "%s#%d: ', host, port), go.addr(host, port)
	local tcp, err = go.socket(addr, true)
	if not tcp then error(msg..err) end
	go(function ()
		local addr, ok, err = tcp:getsockname(), 0
		while ok do
			local req = {}
			ok, err = go(read_http, go.accept(tcp), req, iface.match)
			if err then warp.log({addr=addr}, 'error', tostring(err)) end
		end
	end)
end

local function help()
	print(string.format('Usage: %s [options] <config>', arg[0]))
	print('Options:')
	print('\t-h,--help        ... print this help')
	print('\t-v               ... verbose logging')
end

-- Parse arguments and start serving
-- go(function()
local k = 1 while k <= #arg do
	local v = arg[k]
	local chr = string.char(v:byte())
	if k < 1 then break
	elseif v == '-v' then
		warp.vlog = function (req, ...) return warp.log(req, 'info', ...) end
	elseif v == '-h' or v == '--help' then
		help()
		return 0
	else
		assert(warp.config(v))
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
	elseif iface.scheme == 'http' then
		http(iface.host, iface.port or 8080, iface)
	else
		error('unknown downstream scheme: ' .. iface.scheme)
	end
end
-- end)

-- Run coroutines
while true do
	local ok, err, co = go.run(1)
	if not ok then
		warp.log(nil, 'error', '%s, %s', err, debug.traceback(co))
	end
end
