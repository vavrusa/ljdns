local utils = {}
local ffi = require('ffi')
local bit = require('bit')

-- Compatibility with older LJ that doesn't have table.clear()
pcall(require, 'table.clear')
if not table.clear then
	table.clear = function (t)  -- luacheck: ignore
		for i, _ in ipairs(t) do
			t[i] = nil
		end
	end
end

-- Return DLL extension
function utils.libname(lib, ver)
	assert(jit)
	local fmt = {
		Windows = '%s%s.dll',
		Linux = '%s.so%s', BSD = '%s.so%s', POSIX = '%s.so%s', Other = '%s.so%s',
		OSX = '%s%s.dylib'
	}
	return string.format(fmt[jit.os], lib, ver and ('.'..ver) or '')
end

-- Return versioned C library
function utils.clib(soname, versions)
	-- Search builtin library version first
	if _G[soname .. '_SONAME'] then
		return ffi.load(_G[soname .. '_SONAME']), 'builtin'
	end
	for _, v in pairs(versions) do
		local ok, lib = pcall(ffi.load, utils.libname(soname, tostring(v)))
		if ok then return lib, v end
	end
end

-- Hexdump from http://lua-users.org/wiki/HexDump
function utils.hexdump(buf)
	if buf == nil then return nil end
	for byte=1, #buf, 16 do
		local chunk = buf:sub(byte, byte+15)
		io.write(string.format('%08X  ',byte-1))
		chunk:gsub('.', function (c) io.write(string.format('%02X ',string.byte(c))) end)
		io.write(string.rep(' ',3*(16-#chunk)))
		io.write(' ',chunk:gsub('%c','.'),"\n")
	end
end

-- Parse host/port string
function utils.addrparse(s)
	return s:match '([^#]+)', tonumber(s:match '#(%d+)$') or 53
end

-- Use explicit library or search in the library load path
local knot, knot_version = utils.clib('libknot', {5, 6, 7})

-- Export library
utils.knot = knot
utils.knot_version = knot_version

-- Load cdefs for given library version
require(_G['libknot_CDEFS'] or 'dns.cdef')

-- Check whether the helper C library is built
-- It provides several optimized functions helpers
local has_cutil, cutil = pcall(ffi.load, package.searchpath('kdns_clib', package.cpath))
if has_cutil then
	ffi.cdef[[
	/* helper library */
	unsigned mtime(const char *path);
	int dnamecmp(const uint8_t *lhs, const uint8_t *rhs);
	int dnamekey(uint8_t *restrict dst, const uint8_t *restrict src);
	unsigned bucket(unsigned l);
	/* murmurhash3 */
	void MurmurHash3_x86_32  ( const void * key, int len, uint32_t seed, void * out );
	void MurmurHash3_x64_128 ( const void * key, int len, uint32_t seed, void * out );
	]]

	-- Latency bucket
	utils.bucket = cutil.bucket
	utils.mtime = cutil.mtime
end

-- Byte order conversions
local rshift,band = bit.rshift,bit.band
local function n32(x) return x end
local n16 = n32
if ffi.abi('le') then
	n32 = bit.bswap
	function n16(x) return rshift(n32(x), 16) end
end
utils.n32 = n32
utils.n16 = n16

-- Compute RDATA set length
local function rdsetlen(rr)
	local p, len = rr.rrs.data, 0
	for _ = 1, rr:count() do
		local rdlen = knot.knot_rdata_array_size(knot.knot_rdata_rdlen(p + len))
		len = len + rdlen
	end
	return len
end

-- Get RDATA set member
local function rdsetget(rr, n)
	if not n then n = 0 end
	assert(n < rr:count())
	return knot.knot_rdataset_at(rr.rrs, n)
end

local function rdataiter(rr, it)
	-- Iterator is: { position, knot_rdata_t* }
	it[1] = it[1] + 1
	if it[1] < rr:count() then
		local rdata = it[2]
		local rdlen = knot.knot_rdata_rdlen(rdata)
		it[2] = it[2] + knot.knot_rdata_array_size(rdlen)
		return it, rdata
	end
end

-- Domain name wire length
local knot_dname_p = ffi.typeof('knot_dname_t *')
local function dnamelen(dname)
	return (knot.knot_dname_size(ffi.cast(knot_dname_p, dname)))
end

-- Canonically compare domain wire name / keys
local function dnamecmp(lhs, rhs)
	if cutil then
		return (cutil.dnamecmp(lhs.bytes, rhs.bytes))
	end
	return (knot.knot_dname_cmp(lhs, rhs))
end

-- Wire writer
local function wire_tell(w)
	return w.p + w.len
end
local function wire_seek(w, len)
	assert(w.len + len <= w.maxlen)
	w.len = w.len + len
end
local function wire_write(w, val, len, pt)
	assert(w.len + len <= w.maxlen)
	if pt then
		local p = ffi.cast(pt, w.p + w.len)
		p[0] = val
	else
		ffi.copy(w.p + w.len, val, len)
	end
	w.len = w.len + len
end
local function write_u8(w, val) return wire_write(w, val, 1, ffi.typeof('uint8_t *')) end
local function write_u16(w, val) return wire_write(w, n16(val), 2, ffi.typeof('uint16_t *')) end
local function write_u32(w, val) return wire_write(w, n32(val), 4, ffi.typeof('uint32_t *')) end
local function write_bytes(w, val, len) return wire_write(w, val, len or #val, nil) end
local function wire_writer(p, maxlen)
	return {
		p = ffi.cast('char *', p),
		len = 0,
		maxlen = maxlen,
		u8 = write_u8,
		u16 = write_u16,
		u32 = write_u32,
		bytes = write_bytes,
		tell = wire_tell,
		seek = wire_seek
	}
end
utils.wire_writer=wire_writer
-- Wire reader
local function wire_read(w, len, pt)
	assert(w.len + len <= w.maxlen)
	local ret
	if pt then
		local p = ffi.cast(pt, w.p + w.len)
		ret = p[0]
	else
		ret = ffi.string(w.p + w.len, len)
	end
	w.len = w.len + len
	return ret
end
local function read_u8(w)  return wire_read(w, 1, ffi.typeof('uint8_t *')) end
local function read_u16(w) return n16(wire_read(w, 2, ffi.typeof('uint16_t *'))) end
local function read_u32(w) return n16(wire_read(w, 4, ffi.typeof('uint32_t *'))) end
local function read_bytes(w, len) return wire_read(w, len) end
local function wire_reader(p, maxlen)
	return {
		p = ffi.cast('char *', p),
		len = 0,
		maxlen = maxlen,
		u8 = read_u8,
		u16 = read_u16,
		u32 = read_u32,
		bytes = read_bytes,
		tell = wire_tell,
		seek = wire_seek
	}
end
utils.wire_reader=wire_reader

-- Export low level accessors
utils.rdlen = knot.knot_rdata_rdlen
utils.rddata = knot.knot_rdata_data
utils.rdsetlen = rdsetlen
utils.rdsetget = rdsetget
utils.rdataiter = rdataiter
utils.dnamelen = dnamelen
utils.dnamecmp = dnamecmp

-- Inverse table
function utils.itable(t, tolower)
	local it = {}
	for k,v in pairs(t) do it[v] = tolower and string.lower(k) or k end
	return it
end

-- Reverse table
function utils.reverse(t)
	local len = #t
	for i=1, math.floor(len / 2) do
		t[i], t[len - i + 1] = t[len - i + 1], t[i]
	end
end

-- Sort FFI array (0-indexed) using bottom-up heapsort based on GSL-shell [1]
-- Selection-based sorts work better for this workload, as swaps are more expensive
-- [1]: https://github.com/franko/gsl-shell
function utils.sort(array, size)
	local elmsize = ffi.sizeof(array[0])
	local buf = ffi.new('char [?]', elmsize)
	local tmpval = ffi.cast(ffi.typeof(array[0]), buf)
	local lshift = bit.lshift

	local function sift(hole, len)
		local top, j = hole, hole
		-- Trace a path of maximum children (leaf search)
		while lshift(j + 1, 1) < len do
			j = lshift(j + 1, 1)
			if array[j]:lt(array[j - 1]) then j = j - 1 end
			ffi.copy(array + hole, array + j, elmsize)
			hole = j
		end
		if j == rshift(len - 2, 1) and band(len, 1) == 0 then
			j = lshift(j + 1, 1)
			ffi.copy(array + hole, array + (j - 1), elmsize)
			hole = j - 1
		end
		-- Sift the original element one level up (Floyd's version)
		j = rshift(hole - 1, 1)
		while top < hole and array[j]:lt(tmpval) do
			ffi.copy(array + hole, array + j, elmsize)
			hole = j
			j = rshift(j - 1, 1)
		end
		ffi.copy(array + hole, tmpval, elmsize)
	end

	-- Heapify and sort by sifting heap top
	for i = rshift(size - 2, 1), 0, -1 do
		ffi.copy(tmpval, array + i, elmsize)
		sift(i, size, nil)
	end
	-- Sort heap
	for i = size - 1, 1, -1 do
		ffi.copy(tmpval, array + i, elmsize)
		ffi.copy(array + i, array, elmsize)
		sift(0, i, nil)
	end
end

local function bsearch(array, len, owner, steps)
	-- Number of steps is specialized, this allows unrolling
	if not steps then steps = math.log(len, 2) end
	local low = 0
	for _ = 1, steps do
		len = rshift(len, 1)
		local r1 = dnamecmp(array[low + len]:owner(), owner)
		if     r1  < 0 then low = low + len + 1
		elseif r1 == 0 then return array[low + len]
		end
	end
	return array[low]
end

-- Binary search closure specialized for given array size
local function bsearcher(array, len)
	-- Number of steps can be precomputed
	local steps = math.log(len, 2)
	return function (owner)
		return bsearch(array, len, owner, steps)
	end
	-- Generate force unrolled binary search for this table length
	-- local code = [[
	-- return function (array, m1, key, dnamecmp)
	-- local low = 0
	-- ]]
	-- local m1 = len
	-- for i = 1, steps do
	-- 	m1 = m1 / 2
	-- 	code = code .. string.format([[
	-- 	if dnamecmp(array[low + %d]:owner(), key) <= 0 then
	-- 		low = low + %d
	-- 	end
	-- 	]], m1, m1)
	-- end
	-- code = code .. 'return array[low] end'
	-- -- Compile and wrap in closure with current upvalues
	-- code = loadstring(code)()
	-- return function (owner)
	-- 	return code(array, len, owner, dnamecmp)
	-- end
end
utils.bsearch = bsearch
utils.bsearcher = bsearcher

-- Grow generic buffer
function utils.buffer_grow(arr)
	local nlen = arr.cap
	nlen = nlen < 64 and nlen + 4 or nlen * 2
	local narr = ffi.C.realloc(arr.at, nlen * ffi.sizeof(arr.at[0]))
	if narr == nil then return false end
	arr.at = narr
	arr.cap = nlen
	return true
end

-- Search key representing owner/type pair
-- format: { u8 name [1-255], u16 type }
local function searchkey(owner, type, buf)
	if not buf then
		buf = ffi.new('char [?]', owner:len() + 2)
	end
	-- Convert to lookup format (reversed, label length zeroed)
	local nlen = cutil.dnamekey(buf, owner.bytes)
	-- Write down record type
	buf[nlen] = bit.rshift(type, 8)
	buf[nlen + 1] = bit.band(type, 0xff)
	return buf, nlen + 2
end
utils.searchkey = searchkey

-- Reseed from pseudorandom pool
do
	local pool = io.open('/dev/urandom', 'r')
	local s = ffi.new('uint64_t [1]', os.clock())
	local v = pool:read(ffi.sizeof(s))
	pool:close()
	ffi.copy(s, v, #v)
	math.randomseed(tonumber(s[0]))
end

-- Return non-cryptographic hash of a string
local seed, h32tmp = math.random(0, 0xffffffff), ffi.new('uint32_t [1]')
utils.hash32 = function (data, len)
	len = len or #data
	cutil.MurmurHash3_x86_32(ffi.cast('void *', data), len, seed, h32tmp)
	return h32tmp[0]
end

utils.hash128 = function (data, len, dst)
	dst = dst or ffi.new('char [16]')
	len = len or #data
	cutil.MurmurHash3_x64_128(ffi.cast('void *', data), len, seed, dst)
	return dst
end

-- Export basic OS operations
local has_syscall, S = pcall(require, 'syscall')
if has_syscall and type(S) == 'table' then
	utils.chdir = S.chdir
	utils.mkdir = S.mkdir
	utils.isdir = function (path)
		local st, err = S.lstat(path)
		if not st then return nil, err end
		return st.isdir
	end
	local ip4, ip6 = S.t.sockaddr_in(), S.t.sockaddr_in6()
	utils.inaddr = function (addr, port, n)
		n = n or #addr
		port = port or 0
		if n == 4 then
			ip4.port = port
			ffi.copy(ip4.addr, addr, n)
			return ip4
		elseif n == 16 then
			ip6.port = port
			ffi.copy(ip6.sin6_addr, addr, n)
			return ip6
		end
	end
	utils.ls = function (path)
		return S.util.dirtable(path, true)
	end
end

return utils
