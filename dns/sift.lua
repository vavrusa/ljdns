local ffi = require('ffi')
local kdns = require('dns')
local utils, rrparser = require('dns.utils'), require('dns.rrparser')

-- Compile query string/table into filter function
-- e.g. 'TXT' => filter matching TXT records
--      'rdata~=A(1.2.3.4)' => match all except A RDATA==1.2.3.4'
-- See examples/zq.lua
local function makefilter(query)
	if type(query) == 'string' then query = {query} end
	local filters, farg = {}, {}
	for _,t in ipairs(query) do
		local k,op,v = t:match('(%w+)([~!=><]+)(%S+)')
		if not v then
			local tstr = t:match('%w+')
			if tstr and kdns.type[tstr] then
				k = (#tstr == #t) and 'type' or 'rdata'
				v = t
				op = '=='
			else -- Owner filter
				k = 'owner'
				op = '=='
				v = t
			end
		end
		-- Normalize operator
		if op == '=' or op == 'is' then op = '=='
		elseif op == '!=' then op = '~='
		end
		-- Normalize inversion
		local opref = ''
		if op == '~=' then opref = 'not ' op = '==' end
		-- Select left operand
		if k == 'owner' then
			local owner, _ = v:match('([^~]+)~?(%d*)')
			local meta = 'equals'
			if owner:sub(1,1) == '*' then
				owner = owner:sub(3)
				meta = 'parentof'
			end
			owner = kdns.dname.parse(owner)
			-- TODO(marek): fuzzy search with N allowed edit distance
			-- fuzzy = tonumber(fuzzy)
			table.insert(farg, owner)
			table.insert(filters, string.format('(%sargs[%d]:%s(owner))', opref, #farg, meta))
		elseif k == 'ttl' then
			table.insert(filters, string.format('%s(%s%s%s)', opref, k, op, v))
		elseif k == 'type' then
			table.insert(filters, string.format('%s(rtype%s%d)', opref, op, kdns.type[v]))
		elseif k == 'rdata' then
			-- Parse type and text format and attempt to parse it into wire format
			local rt, rv, rwire = v:match('(%w+)%(([^)]+)%)$')
			-- Raw hex-encoded RDATA is not prefixed with type
			if not rt then
				rwire = v:gsub("\\x(%x%x)",function (x) return string.char(tonumber(x,16)) end)
			-- Type-specific RDATA, attempt to parse
			elseif rt and rv then
				rt = string.upper(rt)
				rwire = kdns.rdata.parse(string.format('%s %s', rt, rv))
				table.insert(filters, string.format('(rtype==%d)', kdns.type[rt]))
			end
			if not rwire then error(string.format('invalid rdata: "%s"', v)) end
			table.insert(farg, rwire)
			table.insert(filters, string.format('(%sstring.find(rdata,args[%d],1,true))', opref, #farg))
		else
			return nil, string.format('unknown filter "%s"', t)
		end
	end
	-- Compile filter function
	local fdecl = table.concat(filters, ' and ')
	if #fdecl == 0 then fdecl = 'true' end
	local ok, filter = pcall(loadstring(
		string.format('return function(owner, rtype, ttl, rdata, args) return %s end', fdecl)))
	if not ok or filter == nil then
		return nil, string.format('bad filter function "%s"', fdecl)
	end
	-- Clear temporary data and return closure
	fdecl, filters, query = nil, nil, nil -- luacheck: ignore
	return function(owner, rtype, ttl, rdata)
		return filter(owner, rtype, ttl, rdata, farg)
	end
end

local function sink_print()
	local count = 0
	return function (owner, type, ttl, rdata)
		if not owner then return count end
		io.write(kdns.rrset(owner, type):add(rdata, ttl):tostring())
		count = count + 1
		return true
	end
end

local function sink_table()
	local capture = {}
	return function (owner, type, ttl, rdata)
		if not owner then return capture end
		table.insert(capture, kdns.rrset(owner, type):add(rdata, ttl))
		return true
	end
end

local function sink_set()
	local capture = rrparser.set()
	local inserted = 0
	return function (owner, type, ttl, rdata)
		if not owner then return capture, inserted end
		-- We'll initialize pre-allocated block to save some ticks
		local rrset = capture:newrr(true)
		rrset._owner = nil
		rrset.rrs.data = nil
		rrset:init(owner, type):add(rdata, ttl)
		inserted = inserted + 1
		return true
	end
end

local lmdb_ok, lmdb = pcall(require, 'dns.lmdb')
local function sink_lmdb(env, db, txn)
	if not lmdb_ok then return nil, 'lmdb sink not supported' end
	if not db then txn, db = assert(env:open()) end
	local key, val = lmdb.val_t(), lmdb.val_t()
	local ttlbuf = ffi.new('uint32_t [1]')
	local inserted = 0
	return function (owner, type, ttl, rdata)
		if not owner then
			txn:commit()
			return env, inserted, db
		end
		-- Create search key
		key.data, key.size = utils.searchkey(owner, type)
		-- Insert into LMDB
		local rdlen = #rdata
		val.data, val.size = nil, ffi.sizeof(ttlbuf) + rdlen
		assert(txn:put(key, val, 'reserve'))
		-- Serialize RR set
		ttlbuf[0] = ttl
		ffi.copy(val.data, ttlbuf, ffi.sizeof(ttlbuf))
		ffi.copy(ffi.cast('char *', val.data) + ffi.sizeof(ttlbuf), rdata, rdlen)
		inserted = inserted + 1
		return true
	end
end

local function sink_json()
	local capture = {}
	local rr = ffi.gc(kdns.rrset(nil, 0), kdns.rrset.clear)
	local fmt = '{ "name": "%s", "type": %d, "TTL": %d, "data": %s }'
	return function (owner, type, ttl, rdata)
		if not owner then
			return string.format('[%s]', table.concat(capture, ','))
		end
		-- Set data for RR set for printing
		rr.raw_type = type
		rr:add(rdata, ttl)
		-- Convert to JSON entry
		local rdata_text = rr:tostring(0)
		if rdata_text:byte() ~= 34 then
			rdata_text = '"'..rdata_text..'"'
		end
		table.insert(capture, string.format(fmt, owner, type, ttl, rdata_text))
		rr:clear()
		return true
	end
end

local function zone(zonefile, sink, filter, limit)
	if not zonefile then return false end
	-- Create sink and parser instance
	if not sink then sink = sink_print() end
	local parser = assert(rrparser.new())
	local ok, err = parser:open(zonefile)
	if not ok then
		return ok, err
	end
	-- Process all records
	local last_name = nil
	while parser:parse() do
		local owner_dname = kdns.todname(parser.r_owner)
		local rdata = ffi.string(parser.r_data, parser.r_data_length)
		-- When limit is placed on the number of results, continue matching
		-- results only as long as owner doesn't change, after that, stop
		if last_name then
			if not last_name:equals(owner_dname) then break end
		end
		-- Match current record against filter
		if not filter or filter(owner_dname, parser.r_type, parser.r_ttl, rdata) then
			-- When limit is placed on the number of results, continue matching
			-- results only as long as owner doesn't change, after that, stop
			if not last_name and limit then
				limit = limit - 1
				if limit <= 0 then last_name = owner_dname:copy() end
			end
			if not sink(owner_dname, parser.r_type, parser.r_ttl, rdata) then
				break
			end
		end
	end
	return sink(nil)
end

return {
	zone = zone,
	makefilter = makefilter,
	printer = sink_print,
	jsonify = sink_json,
	table = sink_table,
	set = sink_set,
	lmdb = sink_lmdb,
}