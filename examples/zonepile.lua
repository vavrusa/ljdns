#!/usr/bin/env luajit
local kdns = require('kdns')
local nio = require('kdns.io')
local rrparser = require('kdns.rrparser')
local ffi = require('ffi')
local dname_p = ffi.typeof('knot_dname_t *')
-- Globals
local pile = '.'
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
local function async_write(socket, msg)
	nio.send(msg, socket)
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
	-- @todo Sanitize and pick the right zone
	local qname = kdns.dname(query:qname()):tostring()
	local zonefile = pile..qname..'zone'
	-- Start streaming answer
	local answer = kdns.packet(65535)
	query:toanswer(answer)
	print(string.format('[%s] streaming to %s#%d', qname, socket:getpeername()))
	local tstart = nio.now()
	local stream = rrparser.stream(zonefile)
	local soa, rr = nil, stream()
	local nrrs, npkts = 0,0
	while rr do
		local rrset = kdns.rrset(nil, rr.type)
		rrset._owner = ffi.cast(dname_p, rr.owner)
		-- @todo: Parse them into RDATA format as well and then static assign
		--        this is cheaper than fragmented mallocs
		rrset:add(rr.rdata, rr.ttl)
		-- Keep SOA reference
		if rr.type == kdns.type.SOA then soa = rrset:copy() end
		nrrs = nrrs + 1
		npkts = npkts + async_insert(socket, query, answer, rrset)
		-- Invalidate static memory
		rrset._owner = nil
		rr = stream()
	end
	-- Stream closing records
	if query:qtype() == kdns.type.AXFR then
		async_insert(socket, query, answer, soa)
	end
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
	
