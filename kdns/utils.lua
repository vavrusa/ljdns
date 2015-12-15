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

-- Byte order conversions
local function n32(x) return x end
local n16 = n32
if ffi.abi('le') then
	n32 = bit.bswap
	function n16(x) return bit.rshift(n32(x), 16) end
end
utils.n32 = n32
utils.n16 = n16

local function lg2(a)
    local c = 0
    while a > 0 do
        a = bit.rshift(a, 1)
        c = c + 1
    end
    return c - 1
end

-- Domain name in lookup format
local dnamekey_t = ffi.typeof('uint8_t [256]')
ffi.cdef[[
int memcmp(const void *a, const void *b, size_t len);
]]
local C, knot = ffi.C, ffi.load(utils.dll_versioned('libknot', '2'))
local function dnamekey(dname, dst)
	dst = dst or dnamekey_t()
	knot.knot_dname_lf(dst, dname, nil)
	return dst
end
-- Canonically compare domain name / keys
local lhs_dk, rhs_dk = dnamekey_t(), dnamekey_t()
local function dnamecmp(lhs, rhs)
	local lkey = ffi.istype(dnamekey_t, lhs) and lhs or dnamekey(lhs, lhs_dk)
	local rkey = ffi.istype(dnamekey_t, rhs) and rhs or dnamekey(rhs, rhs_dk)
	local diff = lkey[0] - rkey[0]
	local ret = C.memcmp(lkey + 1, rkey + 1, diff < 0 and lkey[0] or rkey[0])
	if ret == 0 then ret = diff end
	return ret
end

-- Export dname comparators
utils.dnamekey = dnamekey
utils.dnamecmp = dnamecmp

-- Sort FFI array (0-indexed) using bottom-up heapsort adapted from GSL-shell [1]
-- * Copyright (C) 2009-2012 Francesco Abbate
-- * Published under GNU GENERAL PUBLIC LICENSE, version 3
-- Selection-based sorts work better for this workload, as swaps are more expensive
-- [1]: https://github.com/franko/gsl-shell
function utils.sort(array, len)
	local elmsize = ffi.sizeof(array[0])
	local buf = ffi.new('char [?]', elmsize)
	local tmpval = ffi.cast(ffi.typeof(array[0]), buf)
	local tmpval_dk = dnamekey_t()
	local lshift, rshift, band = bit.lshift, bit.rshift, bit.band

	local function siftup(hole, len)
		local top, j = hole, hole
		-- Trace a path of maximum children (leaf search)
		while lshift(j + 1, 1) < len do
			j = lshift(j + 1, 1)
			j = array[j]:lt(array[(j - 1)]) and j - 1 or j
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
		while top < hole and array[j]:lt(tmpval, tmpval_dk) do
			ffi.copy(array + hole, array + j, elmsize)
			hole = j
			j = rshift(j - 1,1)
		end
		ffi.copy(array + hole, tmpval, elmsize)
	end

	-- Heapify and sort by sifting heap top
	for i = rshift(len - 2, 1), 0, -1 do
		ffi.copy(tmpval, array + i, elmsize)
		dnamekey(tmpval._owner, tmpval_dk) -- Cache tmp dname key
		siftup(i, len)
	end
	for i = len - 1, 1, -1 do
		ffi.copy(tmpval, array + i, elmsize)
		ffi.copy(array + i, array, elmsize)
		dnamekey(tmpval._owner, tmpval_dk) -- Cache tmp dname key
		siftup(0, i)
	end
end

-- Binary search
local rshift = bit.rshift
local function bsearch(array, len, owner, steps)
	local low = 0
	-- Number of steps is specialized, this allows unrolling
	steps = steps or lg2(len)
	-- Hoist the dname search key
	-- print('searching', owner)
	local key = ffi.istype(dnamekey_t, owner) and owner or dnamekey(owner, rhs_dk)
	for i = 0, steps do
		len = rshift(len + 1, 1)
		local r1 = dnamecmp(array[low + len]._owner, key)
		-- print(r1, len, low, array[low + len]._owner)
		if r1 <= 0 then low = low + len end
	end
	--return dnamecmp(array[low], key) == 0 and:equals()
	-- print('-->', array[18]._owner, array[19]._owner, array[low]._owner)
	return array[low]
end

-- Binary search closure
local function bsearcher(array, len)
	-- Number of steps can be precomputed
	-- local steps = lg2(len)
	-- return function (owner)
	-- 	return bsearch(array, len, owner, steps)
	-- end
	-- Generate unrolled binary search for this table length
	local steps = lg2(len)
	local code = {[[
	return function (array, m1, key, dnamecmp)
	local low = 0
	]]}
	for i = 0, steps do
		table.insert(code, [[
		m1 = m1 / 2
		local r1 = dnamecmp(array[low+m1]._owner, key)
		if r1 <= 0 then low = low + m1 end	
		]])
	end
	table.insert(code, 'return array[low] end')
	-- Compile and wrap in closure with current upvalues
	code = loadstring(table.concat(code))()
	return function (owner)
		local key = ffi.istype(dnamekey_t, owner) and owner or dnamekey(owner, rhs_dk)
		return code(array, len, key, dnamecmp)
	end
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

return utils