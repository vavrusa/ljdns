local lmdb = require('dns.lmdb')
local dns = require('dns')
local ffi = require('ffi')
local tokey = dns.utils.searchkey

local M = {}

local entry_t = ffi.typeof('struct { uint16_t count; uint8_t data[?]; }')
local entry_pt = ffi.typeof('struct { uint16_t count; uint8_t data[]; } *')

local key_buf = ffi.new('char [258]')
local val_buf = ffi.new(entry_t, 65535)

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
	rr.raw_data = entry.data
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
	return txn:put(lmdb.val_t(len, key), data), ffi.string(key, len)
end

local function get(txn, name, type, rr)
	local key, len = tokey(name, type, key_buf)
	local v = txn:get(lmdb.val_t(len, key))
	if not v or v.size == 0 then return end
	return toshallow(rr, name, type, v)
end

local function del(txn, name, type)
	local len
	if type then
		name, len = tokey(name, type, key_buf)
	end
	return txn:del(lmdb.val_t(len or #name, name))
end

local function zone(txn, name, rr)
	-- Find SOA for longest prefix of a name
	local p = name.bytes
	for _ = 1, name:labels() do
		local key, len = tokey(p, dns.type.SOA, key_buf)
		local v = txn:get(lmdb.val_t(len, key))
		if v then
			return toshallow(rr, dns.dname(p, len - 2), dns.type.SOA, v)
		end
		p = p + (p[0] + 1)
	end
end

local function isprefix(prefix, key, len)
	return not (prefix.size < len or ffi.C.memcmp(prefix.data, key, len - 2) ~= 0)
end

local function scan(txn, name)
	local cur = txn:cursor()
	local key, len = tokey(name, 0, key_buf)
	-- Trim type to get zone prefix
	local ok = cur:seek(lmdb.val_t(len - 2, key))
	local t = {}
	-- If it can't find the prefix, bail
	if not ok then return t end
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

local function encloser(txn, name, soa, rr)
	-- Search name prefixes for name encloser
	local cur = txn:cursor()
	local p = name.bytes
	local encloser, cut
	-- Search all prefixes, ending at apex
	for _ = 1, name:labels() - soa:owner():labels() do
		p = p + (p[0] + 1)
		local key, len = tokey(p, dns.type.NS, key_buf + 2)
		-- Get all prefixes below this label
		local found = cur:seek(lmdb.val_t(len - 2, key))
		-- Check if we found an encloser
		if not encloser and found and isprefix(found, key, len) then
			-- TODO: search for covering wildcard
			encloser = dns.dname(p, len - 2)
		end
		-- Check if this prefix is a zone cut
		found, cut = cur:seek(lmdb.val_t(len, key), nil, lmdb.op.SET)
		if found then
			encloser, cut = nil, toshallow(rr, dns.dname(p, len - 2), dns.type.NS, cut)
			break
		end
	end
	cur:close()
	return encloser, cut
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
	encloser = function (self, txn, name, soa, rr)
		return encloser(txn, name, soa, rr)
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