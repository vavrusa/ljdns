#!/usr/bin/env luajit
local kdns = require('dns')
local sift = require('dns.sift')
local utils = require('dns.utils')
-- Parameters
local function help()
	print(string.format('Usage: %s [options] [filter] [filter2] ... zonefile', arg[0]))
	print('Options:')
	print('\t-h,--help        ... print this help')
	print('\t-s               ... sort output in canonical order')
	print('\t-1               ... get first result only')
	print('\t-f text|json     ... format output to appropriate format')
	print('Example filters:')
	print('\tSOA              ... search for all SOA records')
	print('\ttype~=SOA        ... search for other records than SOA')
	print('\tdomain.cz        ... search name equal to "domain.cz"')
	print('\towner=domain.cz  ... same as above')
	print('\t*.cz             ... search all names at/below cz (wildcard expansion)')
	print('\tA(1.2.3.4)       ... search all A records with RDATA=1.2.3.4')
	print('\trdata~=\\x02cz    ... search records whose RDATA doesn\'t contain "\\x02cz" (C-like escaped string)')
	print('\tttl<=3600        ... search records where TTL is lower or equal to 3600')
end
-- Parse CLI arguments
if #arg < 1 then help() return 1 end
local zone, format, timeit, sort, limit, query = nil, 'text', false, false, nil, {}
local filters, farg = {}, {}
local k = 1 while k <= #arg do
	local v = arg[k]
	if v == '-h' or v == '--help' then return help()
	elseif v == '-t' then timeit = true
	elseif v == '-s' then sort = true
	elseif v == '-1' then limit = 1
	elseif v == '-f' then
		k = k + 1
		format = arg[k]
	elseif k == #arg then zone = v
	else table.insert(query, v)
	end
	k = k + 1
end
-- Compile filter function
local filter, err = sift.makefilter(query)
if not filter then
	error(err)
end
-- Output formatters
local sink = sift.printer()
if format == 'json' then sink = sift.jsonify() end
if sort then
	if format ~= 'text' then error('cannot sort in other format than "text"') end
	sink = sift.set()
end
-- Filter stream
local elapsed = timeit and kdns.io.now()
local cap, err = sift.zone(zone, sink, filter, limit)
if not cap then
	error(err)
end
if timeit then
	local nrr = 0
	if     type(cap) == 'number' then nrr = cap
	elseif type(cap) == 'table'  then nrr = #cap
	end
	elapsed = kdns.io.now() - elapsed
	io.stderr:write(string.format('; parsed in %.02f msec (%d records)\n', elapsed * 1000.0, nrr))
end
-- Sorted output
if sort then
	cap:sort()
	for i = 0, #cap - 1 do
		io.write(cap.at[i]:tostring())
	end
end
if type(cap) == 'string' then print(cap) end
