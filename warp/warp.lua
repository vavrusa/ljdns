#!/usr/bin/env luajit
local S = require('syscall')
local dns = require('dns')
local warp = require('warp.init')
local nb, utils = require('dns.nbio'), require('dns.utils')
local ffi = require('ffi')

-- Support OpenResty modules
_G.require = require('warp.vendor.resty').require
-- Throttle readers when outstanding requests start piling up
local concurrency_backpressure = 256

-- Writer closures for UDP and TCP
local function writer_udp(req, msg)
	return nb.udpsend(req.sock, msg, req.addr)
end
local function writer_tcp(req, msg)
	return nb.tcpsend(req.sock, msg)
end

-- TCP can pipeline multiple queries in single connection
local function read_tcp(sock, routemap)
	local addr, queries, co = sock:getpeername(), 0
	while true do
		local req = warp.request(sock, addr, true)
		-- Read query off socket
		local ok, err = nb.tcprecv(sock, req.query)
		if ok == 0 then break end
		if not ok then req:log('error', err) break end
		-- Spawn off new coroutine for request
		req.query.size = ok
		ok, err, co = nb.go(warp.serve, req, writer_tcp, routemap)
		if not ok then req:log('error', '%s, %s', err, debug.traceback(co)) end
		queries = queries + 1
	end
	-- Do not wait for GC
	sock:close()
end

-- Bind to sockets and start serving
local function udp(host, port, iface)
	local sock = nb.socket(nb.family(host), 'dgram')
	sock:bind(host, port)
	warp.vlog(nil, string.format('udp "%s#%d: listening', host, port))
	local addr, ok, err, co = sock:getsockname(), 0
	for _ = 1, concurrency_backpressure/4 do
		nb.go(function()
			local addr = nb.addr()
			local n = 0
			while ok do
				-- Fetch next request off freelist
				local req = warp.request(sock, addr)
				ok, err = nb.udprecv(sock, req.query, addr)
				if ok then
					req.query.size = ok
					ok, err, co = pcall(warp.serve, req, writer_udp, iface.match)
				end
				if err then
					req:log('error', '%s, %s', err, debug.traceback(co))
				end
			end
		end)
	end
end

local function tcp(host, port, iface)
	local sock = nb.socket(nb.family(host), 'stream')
	sock:bind(host, port)
	warp.vlog(nil, string.format('tcp "%s#%d: listening', host, port))
	nb.go(function ()
		local ok, err = true
		while ok do
			-- Backpressure for new clients
			while nb.coroutines > concurrency_backpressure do
				coroutine.yield()
			end
			ok, err = nb.go(read_tcp, sock:accept(), iface.match)
			if err then
				warp.log({addr=nb.addr(port, host)}, 'error', tostring(err))
			end
		end
	end)
end

local function tls(host, port, iface)
	-- Create bound sockets
	local msg = string.format('tls "%s#%d: ', host, port)
	local sock = nb.socket(nb.family(host), 'stream')
	sock:bind(host, port)
	-- Open X.509 credentials and create TLS connection upgrade closure
	local tls = require('dns.tls')
	local cred, err = tls.creds.x509(iface.opt)
	if not cred then error(msg .. err) end
	local function read_tls(sock, routemap)
		sock = assert(tls.server(sock, cred))
		return read_tcp(sock, routemap)
	end
	warp.vlog(nil, msg .. 'listening')
	nb.go(function ()
		local ok, err = true
		while ok do
			ok, err = nb.go(read_tls, sock:accept(), iface.match)
			if err then
				warp.log({addr=nb.addr(port, host)}, 'error', tostring(err))
			end
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
	req.sock, req.addr = sock, S.getpeername(sock.fd)
	-- TODO: worry about partial header reads
	local msg = assert(sock:receive())
	if msg and #msg > 0 then
		req.method, req.url, req.proto = msg:match('(%S+)%s(%S+)%s([^\n]+)')
		local ok, err = pcall(warp.api, req, write_http, route)
		if not ok then warp.log(req, 'error', err) end
	end
	sock:close()
end

local function http(host, port, iface)
	local sock = nb.socket(nb.family(host), 'stream')
	sock:bind(host, port)
	nb.go(function ()
		local ok, err = true
		while ok do
			local req = {}
			ok, err = nb.go(read_http, sock:accept(), req, iface.match)
			if err then warp.log(req, 'error', tostring(err)) end
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
	local ok, err, co = nb.run(1)
	if not ok then
		warp.log(nil, 'error', '%s, %s', err, debug.traceback(co))
	end
end
