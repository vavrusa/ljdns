local lmdb = require('dns.lmdb')
local dns = require('dns')
local ffi = require('ffi')
local tokey = dns.utils.searchkey

local M = {}

-- Storage format in the DB
local entry_t = ffi.typeof('struct { uint16_t count; uint8_t data[?]; }')
local entry_pt = ffi.typeof('struct { uint16_t count; uint8_t data[]; } *')

-- Cached temporary buffers
local key_buf = ffi.new('char [258]')
local val_buf = ffi.new(entry_t, 65535)
local mkey, mval = lmdb.val_t(), lmdb.val_t()

local function tomdb(len, data)
	mkey.data, mkey.size = data, len
	return mkey
end

local function toshallow(rr, owner, type, v)
	-- Initialize RR set with shallow copy of the data
	-- that is valid only for duration of the transaction
	-- for this purpose, RR set has a different gc to only clear owner
	if not rr then
		rr = dns.rrset(nil, 0)
		ffi.gc(rr, dns.rrset.init)
	end
	local entry = ffi.cast(entry_pt, v.data)
	rr:init(owner, type)
	rr.raw_data = ffi.cast('void *', entry.data)
	rr.rdcount = entry.count
	return rr
end

local function set(txn, rr)
	local key, len = tokey(rr:owner(), rr:type(), key_buf)
	-- Serialise value and metadata
	local rdlen = dns.utils.rdsetlen(rr)
	assert(rdlen > 0 and rdlen < 65535)
	val_buf.count = rr.rdcount
	ffi.copy(val_buf.data, rr.raw_data, rdlen)
	local data = lmdb.val_t(ffi.offsetof(entry_t, 'data') + rdlen, val_buf)
	-- Insert into storage
	local ok, err = txn:put(lmdb.val_t(len, key), data)
	if err then return nil, err end
	return true, ffi.string(key, len)
end

local function get(txn, name, type, rr)
	local key, len = tokey(name, type, key_buf)
	local v = txn:get(lmdb.val_t(len, key))
	if not v or v.size == 0 then return end
	return toshallow(rr, name, type, v)
end

local function del(txn, name, type)
	local len
	if type then -- Format storage key
		name, len = tokey(name, type, key_buf)
	end
	return txn:del(lmdb.val_t(len or #name, name))
end

local function zone(txn, name, rr)
	-- Find SOA for longest prefix of a name
	local p = name.bytes
	for _ = 1, name:labels() do
		local key, len = tokey(dns.todname(p), dns.type.SOA, key_buf)
		local v = txn:get(tomdb(len, key), mval)
		if v then
			return toshallow(rr, dns.dname(p, len - 2), dns.type.SOA, v)
		end
		p = p + (p[0] + 1)
	end
end

local function isprefix(prefix, key, len)
	len = len - 2 -- Trim TYPE
	if prefix.size < len then return false end
	return ffi.C.memcmp(prefix.data, key, len) == 0
end

local function keywildcard(key)
	if key.size >= 4 then
		-- Ends with ['*', 0x00, TYPE, TYPE]
		local bytes, last = ffi.cast('char *', key.data), key.size - 1
		return bytes[last - 3] == 0x2a and bytes[last - 2] == 0
	end
end

local function keytype(key)
	local bytes, last = ffi.cast('char *', key.data), key.size - 1
	return bit.bor(bit.lshift(bytes[last - 1], 8), bytes[last])
end

local function scan(txn, name)
	local cur = txn:cursor()
	local key, len = tokey(name, 0, key_buf)
	-- Trim type to get zone prefix
	local ok = cur:seek(lmdb.val_t(len - 2, key))
	local t = {}
	-- If it can't find the prefix, bail
	if not ok then
		cur:close()
		return t
	end
	-- Find all keys matching given prefix
	local ignore
	for k,_ in ipairs(cur) do
		-- Stop when name doesn't match given prefix
		if not isprefix(k, key, len) then
			break
		end
		-- Ignore subset belonging to different zone cut
		local key = ffi.string(k.data, k.size)
		if #key > len and key:find('\x00\x06', #key - 1, true) then
			ignore = key
		end
		if ignore then
			-- Check if current prefix is out of ignored subzone
			if not key:find(ignore, 1, true) then
				ignore, t[key] = nil, true
			end
		else
			t[key] = true
		end
	end
	cur:close()
	return t
end

local function match(txn, soa, name, type, rr)
	-- Search name prefixes for name encloser
	local p = name.bytes
	local encloser, cut, wildcard, rtype
	-- Check if a complete match exists first
	local key, len = tokey(dns.todname(p), type, key_buf)
	local v, found = txn:get(tomdb(len, key), mval)
	if found then
		encloser = toshallow(rr, name, type, v)
	else
		-- Check if CNAME for this name exists
		key[len - 2], key[len - 1] = 0, dns.type.CNAME
		v, found = txn:get(tomdb(len, key), v)
		if found then
			encloser = toshallow(rr, name, dns.type.CNAME, v)
		end
	end
	-- Scan all prefixes, ending at zone apex
	for _ = 1, name:labels() - soa:owner():labels() - 1 do
		p = p + (p[0] + 1)
		-- Find a possible zone cut
		key, len = tokey(dns.todname(p), dns.type.NS, key_buf)
		v, found = txn:get(tomdb(len, key), v)
		if found then
			encloser, cut = nil, toshallow(rr, dns.todname(p), dns.type.NS, v)
			break
		end
		-- Find a covering wildcard by extending search key
		if not encloser then
			local suffix = ffi.cast('char *', key + len - 2)
			suffix[0], suffix[1] = 0x2a, 0x00 -- Wildcard label
			suffix[2], suffix[3] = bit.rshift(type, 8), bit.band(type, 0xff)
			-- Find wildcard matching searched type
			v, found = txn:get(tomdb(len + 2, key), v)
			if found then
				encloser, wildcard = toshallow(rr, name, type, v), true
			else
				-- Find wildcard matching CNAME
				suffix[2], suffix[3] = 0, dns.type.CNAME
				v, found = txn:get(tomdb(len + 2, key), v)
				if found then
					encloser, wildcard = toshallow(rr, name, dns.type.CNAME, v), true
				end
			end
			-- TODO: find closest encloser to shortcut deep labels
		end
	end
	return encloser, cut, wildcard
end

local function addglue(txn, ns, rr, dst)
	for _, rd in ipairs(ns) do
		local target = dns.todname(rd:data())
		local key, len = tokey(target, dns.type.AAAA, key_buf)
		-- Find AAAA glue
		local v = txn:get(lmdb.val_t(len, key))
		if v then
			toshallow(rr, target, dns.type.AAAA, v)
			table.insert(dst, rr:copy())
		end
		--- Find A glue
		key[len - 1] = dns.type.A
		v = txn:get(lmdb.val_t(len, key))
		if v then
			toshallow(rr, target, dns.type.A, v)
			table.insert(dst, rr:copy())
		end
	end
end

local meta = {
	txn = function (self, rdonly)
		return self.env:txn(self.db, rdonly and 'rdonly')
	end,
	set = function (self, txn, rr)
		return set(txn, rr)
	end,
	get = function (self, txn, name, type, rr)
		return get(txn, name, type)
	end,
	del = function (self, txn, name, type)
		return del(txn, name, type)
	end,
	zone = function (self, txn, name, rr)
		return zone(txn, name)
	end,
	scan = function (self, txn, name)
		return scan(txn, name)
	end,
	match = function (self, txn, soa, name, type, rr)
		return match(txn, soa, name, type, rr)
	end,
	addglue = function (self, txn, ns, rr, dst)
		return addglue(txn, ns, rr, dst)
	end,
}

function M.open(conf)
	conf.path = conf.path or '.'
	conf.size = conf.size or 10 * 1024 * 1024 * 1024
	conf.flags = conf.flags or 'writemap, mapasync'
	-- Open LMDB environment and a single DB
	local env = assert(lmdb.open(conf.path, conf.flags, conf.size, conf.mode, conf.maxdbs))
	local txn, db = assert(env:open())
	assert(txn:commit())
	return setmetatable({env=env,db=db}, {__index = meta})
end

return M