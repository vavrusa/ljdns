local utils = {}
local ffi = require('ffi')
local bit = require('bit')

-- Return DLL extension
function utils.dll_versioned(lib, ver)
	assert(jit)
	local fmt = {
		Windows = '%s.%s.dll',
		Linux = '%s.so.%s', BSD = '%s.so.%s', POSIX = '%s.so.%s', Other = '%s.so.%s',
		OSX = '%s.%s.dylib'
	}
	return string.format(fmt[jit.os], lib, ver)
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

-- FFI + C code
local libknot = ffi.load(utils.dll_versioned('libknot', '2'))
local cutil = ffi.load(package.searchpath('kdns_clib', package.cpath))
ffi.cdef[[
unsigned mtime(const char *path);
int dnamecmp(const uint8_t *lhs, const uint8_t *rhs);
]]

-- Byte order conversions
local function n32(x) return x end
local n16 = n32
if ffi.abi('le') then
	n32 = bit.bswap
	function n16(x) return bit.rshift(n32(x), 16) end
end
utils.n32 = n32
utils.n16 = n16
local rshift,band = bit.rshift,bit.band

-- Compute RDATA set length
local function rdsetlen(rr)
	local len = 0
	for i = 1,rr.rdcount do
		len = len + (libknot.knot_rdata_rdlen(rr.raw_data + len) + 4)
	end
	return len
end

-- Get RDATA set member
local function rdsetget(rr, n)
	assert(n < rr.rdcount)
	local p = rr.raw_data
	for i = 1,n do
		p = p + (libknot.knot_rdata_rdlen(p) + 4)
	end
	return p
end

-- Domain name wire length
local function dnamelenraw(dname)
	local p, i = dname, 0
	assert(p ~= nil)
	while p[i] ~= 0 do
		i = i + p[i] + 1
	end
	return i + 1 -- Add label count
end
local function dnamelen(dname)
	return dnamelenraw(dname.bytes)
end

-- Canonically compare domain wire name / keys
local function dnamecmp(lhs, rhs)
	return cutil.dnamecmp(lhs.bytes, rhs.bytes)
end

-- Export low level accessors
utils.rdsetlen = rdsetlen
utils.rdsetget = rdsetget
utils.dnamelen = dnamelen
utils.dnamelenraw = dnamelenraw
utils.dnamecmp = dnamecmp
utils.dnamecmpraw = cutil.dnamecmp
utils.mtime = cutil.mtime

-- Sort FFI array (0-indexed) using bottom-up heapsort based on GSL-shell [1]
-- Selection-based sorts work better for this workload, as swaps are more expensive
-- [1]: https://github.com/franko/gsl-shell
function utils.sort(array, len)
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
	for i = rshift(len - 2, 1), 0, -1 do
		ffi.copy(tmpval, array + i, elmsize)
		sift(i, len, nil)
	end
	-- Sort heap
	for i = len - 1, 1, -1 do
		ffi.copy(tmpval, array + i, elmsize)
		ffi.copy(array + i, array, elmsize)
		sift(0, i, nil)
	end
end

local function bsearch(array, len, owner, steps)
	-- Number of steps is specialized, this allows unrolling
	if not steps then steps = math.log(len, 2) end
	local low = 0
	for i = 1, steps do
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

-- Export basic OS operations
local _, S = pcall(require, 'syscall')
if S then
	utils.chdir = S.chdir
end

return utils
