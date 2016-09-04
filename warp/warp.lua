#!/usr/bin/env luajit
local S = require('syscall')
local dns = require('dns')
local warp = require('warp.init')
local go, utils = require('dns.nbio'), require('dns.utils')

-- Support OpenResty modules
_G.require = require('warp.vendor.resty').require

-- Load default configuration for now
-- luacheck: ignore
warp.conf(function()
	route {
		lru {},
		whoami {},
		file {
			path = 'zones'
		},
		dnssec {
			algorithm = 'ecdsa_p256_sha256',
		}
	}
end)

-- Writer closures for UDP and TCP
local function writer_udp(req, msg)
	return go.udpsend(req.sock, msg.wire, msg.size, req.addr)
end
local function writer_tcp(req, msg)
	return go.tcpsend(req.sock, msg.wire, msg.size)
end

-- TCP can pipeline multiple queries in single connection
local function read_tcp(sock)
	local addr, queries = sock:getpeername(), 0
	while true do
		local req = warp.request(sock, addr, true)
		-- Read query off socket
		local ok, err = go.tcprecv(sock, req.query.wire, req.query.max_size)
		if ok == 0 then break end
		if err then req:log('error', err) break end
		-- Spawn off new coroutine for request
		if queries > 0 then req.sock = sock:dup() end
		req.query.size = ok
		ok, err = go(warp.serve, req, writer_tcp)
		if not ok then req:log('error', err) end
		queries = queries + 1
	end
	-- Do not wait for GC
	sock:close()
end

-- Bind to sockets and start serving
local function downstream(host, port)
	-- Create bound sockets
	local msg, addr = string.format('interface "%s#%d: ', host, port), go.addr(host, port)
	local tcp, err = go.socket(addr, true)
	if not tcp then error(msg..err) end
	local udp, err = go.socket(addr)
	if not udp then error(msg..err) end
	warp.vlog(nil, msg .. 'listening')
	-- Spawn coroutines for listeners
	go(function()
		local addr, ok, err = udp:getsockname(), 0
		while ok do
			-- Fetch next request off freelist
			local req = warp.request(udp, addr)
			ok, err = go.udprecv(udp, req.query.wire, req.query.max_size, addr)
			if ok then
				req.query.size = ok
				ok, err = go(warp.serve, req, writer_udp)
			end
			if err then req:log('error', tostring(err)) end
		end
	end)
	go(function ()
		local addr, ok, err = tcp:getsockname(), 0
		while ok do
			ok, err = go(read_tcp, go.accept(tcp))
			if err then warp.log({addr=addr}, 'error', tostring(err)) end
		end
	end)
end

local function help()
	print(string.format('Usage: %s [options] <config>', arg[0]))
	print('Options:')
	print('\t-h,--help        ... print this help')
	print('\t-v               ... verbose logging')
	print('\t@<addr>[#port]   ... listen on given address/port (e.g. ::1#53)')
end

-- Parse arguments and start serving
for k,v in next,arg,0 do
	local chr = string.char(v:byte())
	if k < 1 then break
	elseif chr == '@' then
		local host, port = v:match("@([^#]+)"), tonumber(v:match("#(%d+)")) or 53
		downstream(host, port)
	elseif v == '-v' then
		warp.vlog = function (req, ...) return warp.log(req, 'info', ...) end
	elseif v == '-h' or v == '--help' then
		help()
		return 0
	else
		warp.conf(v)
	end
end

-- Enable trace stitching
require('jit.opt').start('minstitch=10')
-- Limit the number of in-flight requests
go.concurrency(64)
-- Run coroutines
local ok, err, co = go.run(1)
if not ok then
	warp.log(nil, 'error', '%s, %s', err, debug.traceback(co))
end
