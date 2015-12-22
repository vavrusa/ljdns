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
local rshift,bxor,arshift,band = bit.rshift,bit.bxor,bit.arshift,bit.band

local function lg2(a)
    local c = 0
    while a > 0 do
        a = rshift(a, 1)
        c = c + 1
    end
    return c - 1
end

-- Branch-free number selector for min/max/alter
-- This is of course more costly (5 instructions + narrowing) than conditional jump,
-- but avoids side traces in tight loops (where dnamecmp is used)
local function choose(x,y,xx,yy)
	return (bxor(band(arshift(x-y, 31), bxor(xx, yy)), yy))
end
local function min(x,y) return choose(x,y,x,y) end
local function max(x,y) return choose(x,y,y,x) end

-- Domain name wire length
local function dnamelen(dname)
	local p, i = dname.bytes, 0
	while p[i] ~= 0 do
		i = i + p[i] + 1
	end
	return i + 1 -- Count terminal label
end

-- Domain name in lookup format
local dnamekey_t = ffi.typeof('uint8_t [256]')
local C, knot = ffi.C, ffi.load(utils.dll_versioned('libknot', '2'))
local function dnamekey(dname, dst)
	dst = dst or dnamekey_t()
	knot.knot_dname_lf(dst, dname.bytes, nil)
	return dst
end

-- Canonically compare domain wire name / keys
local lhs_dk, rhs_dk = dnamekey_t(), dnamekey_t()
local function dnamecmp(lhs, rhs)
	local lkey = ffi.istype(dnamekey_t, lhs) and lhs or dnamekey(lhs, lhs_dk)
	local rkey = ffi.istype(dnamekey_t, rhs) and rhs or dnamekey(rhs, rhs_dk)
	local ret = C.memcmp(lkey + 1, rkey + 1, min(lkey[0], rkey[0]))
	if ret == 0 then ret = lkey[0] - rkey[0] end
	return ret
end

-- Export dname comparators
utils.dnamelen = dnamelen
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
	local lshift = bit.lshift

	local function sift(hole, len, skey)
		local top, j = hole, hole
		-- Trace a path of maximum children (leaf search)
		while lshift(j + 1, 1) < len do
			j = lshift(j + 1, 1)
			-- j = j - tonumber(ffi.cast('int32_t', array[j]:lt(array[(j - 1)])))
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
		while top < hole and array[j]:lt(tmpval, skey) do
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
	local tmpval_dk = dnamekey_t()
	for i = len - 1, 1, -1 do
		ffi.copy(tmpval, array + i, elmsize)
		ffi.copy(array + i, array, elmsize)
		dnamekey(tmpval:owner(), tmpval_dk) -- Cache tmp dname key
		sift(0, i, tmpval_dk)
	end
end

-- Binary search
local function bsearch(array, len, owner, steps)
	-- Hoist the dname search key
	if not ffi.istype(dnamekey_t, owner) then owner = dnamekey(owner, rhs_dk) end
	-- Number of steps is specialized, this allows unrolling
	if not steps then steps = lg2(len) end
	local low = 0
	for i = 0, steps do
		len = rshift(len + 1, 1)
		local r1 = dnamecmp(array[low + len]:owner(), owner)
		if r1 <= 0 then low = low + len end
	end
	return array[low]
end

-- Binary search closure
local function bsearcher(array, len)
	-- Number of steps can be precomputed
	local steps = lg2(len)
	return function (owner)
		return bsearch(array, len, owner, steps)
	end
	-- Generate force unrolled binary search for this table length
	-- local steps = lg2(len)
	-- local code = {[[
	-- return function (array, m1, key, dnamecmp)
	-- local low = 0
	-- ]]}
	-- for i = 0, steps do
	-- 	table.insert(code, [[
	-- 	m1 = m1 / 2
	-- 	local r1 = dnamecmp(array[low+m1]:owner(), key)
	-- 	if r1 <= 0 then low = low + m1 end
	-- 	]])
	-- end
	-- table.insert(code, 'return array[low] end')
	-- -- Compile and wrap in closure with current upvalues
	-- code = loadstring(table.concat(code))()
	-- return function (owner)
	-- 	local key = ffi.istype(dnamekey_t, owner) and owner or dnamekey(owner, rhs_dk)
	-- 	return code(array, len, key, dnamecmp)
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

return utils