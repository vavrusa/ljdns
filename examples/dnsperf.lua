local dns = require('dns')
local nb = require('dns.nbio')

-- Enable trace stitching
require('jit.opt').start('minstitch=5')

-- Parse config options
local tx, rx = 0, 0
local udp = false
local count = 65536
local reps = 1
local host, port = '127.0.0.1', 53
local receiver = false
local k = 1 while k <= #arg do
	local o = arg[k]
	if o == '-r' then
		receiver = true
	elseif o == '-u' then
		udp = true
	elseif o == '-n' then
		reps, k = tonumber(arg[k + 1]), k + 1
	elseif o == '-s' then
		host, k = arg[k + 1], k + 1
	elseif o == '-p' then
		port, k = tonumber(arg[k + 1]), k + 1
	end
	k = k + 1
end

local function client(sock, xchg, resp, i)
	tx = tx + 1
	local query = dns.packet(32)
	query:question('\4test', dns.type.SOA)
	query:id(i)
	assert(xchg(sock, query, resp, true))
	assert(resp:parse())
	rx = rx + 1
end

local function ping(sock, xchg, count)
	local resp = dns.packet(64)
	for i = 0, count - 1 do
		assert(nb.go(client, sock, xchg, resp, i))
	end
end

local function pong(sock, send, recv, addr)
	local msg = dns.packet(64)
	while true do
		msg:clear()
		local n = recv(sock, msg, addr)
		if not n then break end
		rx = rx + 1
		assert(msg:parse())
		msg:qr(true)
		assert(send(sock, msg, addr))
		tx = tx + 1
	end
end

-- Receiver mode
local ts = nb.now()
if receiver and udp then
	local server = nb.socket(nb.family(host), 'dgram')
	server:bind(host, port)
	assert(nb.go(pong, server, nb.udpsend, nb.udprecv, nb.addr()))
elseif receiver and not udp then
	local server = nb.socket(nb.family(host), 'stream')
	server:bind(host, port)
	assert(nb.go(function()
		while true do
			local client = assert(server:accept())
			nb.go(pong, client, nb.tcpsend, nb.tcprecv)
		end
	end))
elseif udp then
	local client = nb.socket(nb.family(host), 'dgram')
	assert(nb.go(function ()
		assert(client:connect(host, port))
		for _ = 1, reps do
			ping(client, nb.udpxchg, count)
		end
	end))
else
	local client = nb.socket(nb.family(host), 'stream')
	assert(nb.go(function ()
		assert(client:connect(host, port))
		for _ = 1, reps do
			ping(client, nb.tcpxchg, count)
		end
	end))
end

local ok, err, co = nb.run()
if not ok then
	print(err, debug.traceback(co))
end

-- Print metrics
local elapsed = (nb.now() - ts)
print(string.format('rx: %d, tx: %d, elapsed: %.02fs, rate: %.02f req/s', rx, tx, elapsed, rx/elapsed))