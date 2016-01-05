#!/usr/bin/env luajit
local kdns = require('kdns')
local nio = require('kdns.io')
local rrparser = require('kdns.rrparser')
local ffi = require('ffi')
-- Globals
local pile = '.'
local valid_types = { [kdns.type.AXFR] = true, [kdns.type.IXFR] = true, [kdns.type.SOA] = true }
local sockets, reverse, listeners, writers, pending = {}, {}, {}, {}, {}
-- Parameters
for k,v in next,arg,0 do
	local chr = string.char(v:byte())
	if k < 1 then break
	elseif chr == '@' then
		local host, port = v:match("@([^#]+)"), v:match("#(%d+)") or 53
		local sock, err = nio.server(host, port, true)
		local msg = string.format('interface "%s#%d: ', host, port)
		if not sock then error(msg..err) end
		print(msg..'listening')
		table.insert(sockets, sock)
		listeners[sock] = true
	else
		if not io.open(v) then error('invalid pile path: '..v) end
		pile = v..'/'
	end
end
-- Set up async callbacks
local function async_write(socket, msg, len)
	nio.send(socket, msg, len)
	table.insert(writers, socket)
	coroutine.yield()
end
local function async_recv(socket)
	coroutine.yield()
	return nio.recv(socket)
end
local function  async_checkout(socket, msg, answer)
	local wire = answer:towire()
	async_write(socket, wire)
	msg:toanswer(answer)
	answer:aa(true)
end
local function  async_insert(socket, msg, answer, rr)
	local npkts = 0
	if not answer:put(rr, true) then
		npkts = npkts + 1
		async_checkout(socket, msg, answer)
		answer:put(rr, true) -- Promise not to access RR afterwards
	end
	return npkts
end
local function async_serve(socket)
	-- Receive and parse message
	local msg = async_recv(socket)
	if not msg then return false end
	local query = kdns.packet(#msg, msg)
	if not query:parse() then return false end
	-- Support only SOA, AXFR and IXFR
	local qtype = query:qtype()
	if not valid_types[qtype] then return false end
	-- Sanitize and pick the right zone
	local qname = kdns.dname(query:qname()):tostring()
	if qname == '.' then qname = 'root.' end
	local zonefile = pile..qname:gsub('/', '_')..'zone'
	-- Start streaming answer
	print(string.format('[%s] streaming to %s#%d', zonefile, socket:getpeername()))
	-- @TODO: rewrite to sift
	local answer = kdns.packet(16384+4096)
	query:toanswer(answer)
	local tstart = nio.now()
	local parser = rrparser.new()
	assert(parser:open(zonefile))
	local soa, nrrs, npkts = nil, 0, 0
	-- Hoist empty RR container alloc
	local rrset = kdns.rrset(nil, 0)
	while parser:parse() do
		-- Purge RR container
		rrset:clear()
		rrset._owner = kdns.todname(parser.r_owner, parser.r_owner_length)
		rrset._type = parser.r_type
		rrset:add(ffi.string(parser.r_data, parser.r_data_length), parser.r_ttl)
		-- Keep SOA reference
		if parser.r_type == kdns.type.SOA then
			soa = rrset:copy()
			if qtype == kdns.type.SOA then break end
		end
		-- Send
		nrrs = nrrs + 1
		npkts = npkts + async_insert(socket, query, answer, rrset)
	end
	-- Invalidate unmanaged memory
	rrset._owner = nil
	-- Stream closing records
	async_insert(socket, query, answer, soa)
	async_write(socket, answer:towire())
	print(string.format('[%s] finished: %d records, %d messages, %d msec', qname, nrrs, npkts, (nio.now() - tstart) * 1000.0))
	return false
end
local function async_update(s)
	if listeners[s] then
		local client = s:accept()
		local co = coroutine.create(async_serve)
		coroutine.resume(co, client)
		if coroutine.status(co) ~= 'dead' then
			reverse[client] = #sockets + 1
			pending[client] = co
			table.insert(sockets, client)
		else
			client:close()
		end
	else
		local ok, err = coroutine.resume(pending[s])
		if not ok or coroutine.status(pending[s]) == 'dead' then
			if err then print(err) end
			table.remove(sockets, reverse[s])
			reverse[s] = nil
			pending[s] = nil
			s:close()
		end
	end
end
-- Start serving
while true do
	local readable, writeable = nio.poll(sockets, writers)
	writers = {}
	for i, s in ipairs(readable) do
		async_update(s)
	end
	for i, s in ipairs(writeable) do
		async_update(s)
	end
end
	
