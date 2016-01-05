#!/usr/bin/env luajit
local kdns = require('kdns')
local sift, utils = require('kdns.sift'), require('kdns.utils')

-- Load up zone
local elapsed = kdns.io.now()
local set, err = sift.zone(arg[1], sift.set())
if not set then error(err) end
elapsed = kdns.io.now() - elapsed
print(string.format('load: %.02f msec (%d rrs)', elapsed * 1000.0, set.len))
-- Sort the set
elapsed = kdns.io.now()
set:sort()
elapsed = kdns.io.now() - elapsed
print(string.format('sort: in %.02f msec', elapsed * 1000.0))
-- Perform random queries
local queries = {}
local N = 16
for i = 1, N do
	local qname = set.at[math.random(0, #set - 1)]:owner()
	table.insert(queries, qname)
end
local searcher = set:searcher()
elapsed = kdns.io.now()
for i = 0, 100000 do
	local qname = queries[i % N + 1]
	local found = searcher(qname)
	assert(qname:equals(found:owner()))
end
elapsed = kdns.io.now() - elapsed
print(string.format('search: %d ops/sec', 100000 / elapsed))
