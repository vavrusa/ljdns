#!/usr/bin/env luajit
local kdns = require('dns')
local sift, utils = require('dns.sift'), require('dns.utils')
local aio = require('dns.nbio')
local lmdb_ok, lmdb = pcall(require, 'dns.lmdb')
local dnssec_ok, dnssec = pcall(require, 'dns.dnssec')

assert(arg[1], 'usage: bench.lua <zonefile>')

local function bench_sift(backend)
	-- Load up zone
	local elapsed = aio.now()
	local set, inserted, where = sift.zone(arg[1], backend)
	if not set then error(inserted) end
	elapsed = aio.now() - elapsed
	print(string.format('load: %.02f msec (%d rrs)', elapsed * 1000.0, inserted))
	return set, where, inserted/32
end

local function bench_sortedset(set, step)
	-- Sort the set
	local elapsed = aio.now()
	set:sort()
	elapsed = aio.now() - elapsed
	print(string.format('sort: in %.02f msec', elapsed * 1000.0))
	-- Perform random queries
	local queries = {}
	for i = 0, #set - 1, step do
		local qname = set.at[i]:owner()
		table.insert(queries, qname)
	end
	local N = #queries
	local searcher = set:searcher()
	elapsed = aio.now()
	for i = 0, 100000 do
		local qname = queries[i % N + 1]
		local found = searcher(qname)
		assert(found)
	end
	elapsed = aio.now() - elapsed
	print(string.format('search: %d ops/sec', 100000 / elapsed))
end

local function bench_lmdb(env, db, step)
	-- Perform random queries
	local txn = assert(env:txn(db, 'rdonly'))
	local queries = {}
	local countdown = 0
	local cur = txn:cursor()
	for i,_ in ipairs(cur) do
		if countdown == 0 then
			table.insert(queries, lmdb.val_t(i.size, i.data))
			countdown = step
		else
			countdown = countdown - 1
		end
	end
	local N = #queries
	cur:close()
	local elapsed = aio.now()
	local val = lmdb.val_t()
	for i = 0, 100000 do
		local query = queries[i % N + 1]
		local found = txn:get(query, val)
		assert(found)
	end
	elapsed = aio.now() - elapsed
	txn:abort()
	print(string.format('search: %d ops/sec', 100000 / elapsed))
end

local function bench_signer(set, test_key)
	local limit = 20000 - 1
	-- Sign selected records in the set
	local key = dnssec.key()
	assert(key:algo(test_key.algorithm))
	assert(key:privkey(test_key.pem))
	assert(key:can_sign())
	local elapsed = aio.now()
	local signer = dnssec.signer(key)
	local rrsigs = {}
	for i = 0, #set - 1 do
		local rr = set.at[i]
		table.insert(rrsigs, signer:sign(rr))
		if i == limit then break end
	end
	elapsed = aio.now() - elapsed
	print(string.format('%s sign: %d ops/sec', test_key.name, #rrsigs / elapsed))
	-- Verify signatures in the set
	elapsed = aio.now()
	for i, rrsig in ipairs(rrsigs) do
		local rr = set.at[i - 1]
		assert(signer:verify(rr, rrsig))
	end
	elapsed = aio.now() - elapsed
	print(string.format('%s verify: %d ops/sec', test_key.name, #rrsigs / elapsed))
end

-- Sorted set + binary search
print('bench: sortedset')
local set, err, step = bench_sift(sift.set())
bench_sortedset(set, step)

-- LMDB backend
print('bench: lmdb')
if lmdb_ok then
	local S = require('syscall')
	local tmpdir = '.tmpbench'
	if S.stat(tmpdir) then
		S.util.rm(tmpdir)
	end
	S.mkdir(tmpdir, '0755')
	local env = assert(lmdb.open(tmpdir, 'writemap, mapasync'))
	local env, db, step = bench_sift(sift.lmdb(env))
	if env then
		bench_lmdb(env, db, step)
	end
	S.util.rm(tmpdir)
end

-- Signer
print('bench: signer')
if dnssec_ok then
	require('spec.helper')
	for _, key in pairs(sample_keys) do
		bench_signer(set, key)
	end
end