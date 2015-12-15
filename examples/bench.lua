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
for i = 1, 10 do
	local qname = set.at[math.random(0, #set - 1)]:owner()
	table.insert(queries, qname)
end
local searcher = set:searcher()
elapsed = kdns.io.now()
for i = 0, 1000000 do
	local qname = queries[i % #queries + 1]
	assert(qname:equals(searcher(qname):owner(), qname))
end
elapsed = kdns.io.now() - elapsed
print(string.format('search: %d ops/sec', 1000000 / elapsed))