local ffi = require('ffi')
local kdns = require('kdns')
local rrparser = require('kdns.rrparser')
local sift = {}

-- Compile query string/table into filter function
-- e.g. 'TXT' => filter matching TXT records
--      'rdata~=A(1.2.3.4)' => match all except A RDATA==1.2.3.4'
-- See examples/zq.lua
local function makefilter(query)
	if type(query) == 'string' then query = {query} end
	local filters, farg = {}, {}
	for i,t in ipairs(query) do
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
			local owner, fuzzy = v:match('([^~]+)~?(%d*)')
			local meta = 'equals'
			if owner:sub(1,1) == '*' then
				owner = owner:sub(3)
				meta = 'parentof'
			end
			owner = kdns.dname.parse(owner)
			fuzzy = tonumber(fuzzy)
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
	fdecl = nil
	filters = nil
	query = nil
	return function(owner, rtype, ttl, rdata)
		return filter(owner, rtype, ttl, rdata, farg)
	end
end

local function sink_print()
	return function (owner, rtype, ttl, rdata)
		if not owner then return true end
		io.write(kdns.rrset(owner, rtype):add(rdata, ttl):tostring())
	end
end

local function sink_table()
	local capture = {}
	return function (owner, type, ttl, rdata)
		if not owner then return capture end
		table.insert(capture, kdns.rrset(owner, type):add(rdata, ttl))
	end
end

local function sink_set()
	local capture = rrparser.set()
	return function (owner, type, ttl, rdata)
		if not owner then return capture end
		local rrset = capture:newrr(true)
		rrset:init(owner, type, nil, true):add(rdata, ttl)
	end
end

local function sink_json()
	local capture = {}
	return function (owner, type, ttl, rdata)
		if not owner then
			for i,v in ipairs(capture) do
				local owner, ttl, type, rdata = v:match("(%S+)%s+(%d+)%s+(%S+)%s+([^\n]+)\n")
				capture[i] = string.format('{ "owner": "%s", "type": "%s", "ttl": %d, "rdata": "%s" }',
					owner, type, ttl, rdata)
			end
			return string.format('[%s]', table.concat(capture, ','))
		end
		table.insert(capture, kdns.rrset(owner, type):add(rdata, ttl):tostring())
	end
end

local function zone(zone, sink, filter)
	if not sink then sink = sink_print() end
	local parser = assert(rrparser.new())
	assert(parser:open(zone))
	while parser:parse() do
		local owner_dname = kdns.todname(parser.r_owner)
		local rdata = ffi.string(parser.r_data, parser.r_data_length)
		if not filter or filter(owner_dname, parser.r_type, parser.r_ttl, rdata) then
			sink(owner_dname, parser.r_type, parser.r_ttl, rdata)
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
}