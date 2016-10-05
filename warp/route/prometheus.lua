local json = require('cjson')
local M = {}

-- Prometheus types
local counter = '# TYPE %s counter\n%s %f'
local histogram = '# TYPE latency histogram'

-- Serve Prometheus in text format
local function serve(self, req, writer)
	local warp = require('warp.init')
	local body = {}
	-- Add all counters
	for k,v in pairs(warp.stats) do
		k = select(1, k:gsub('%.', '_'))
		table.insert(body, string.format(counter, k, k, v))
	end
	-- Sort latency bucket keys
	local keys = {}
	for k, _ in pairs(warp.latency) do
		table.insert(keys, k)
	end
	table.sort(keys)
	local last = keys[#keys]
	-- Add latency histogram
	table.insert(body, histogram)
	local count, sum = 0.0, 0.0
	for _,i in ipairs(keys) do
		local c = warp.latency[i]
		count = count + c
		sum = sum + c * i
		if i == last then i = '+Inf' end
		table.insert(body, string.format('latency_bucket{le=%s} %f', i, c))
	end
	table.insert(body, string.format('latency_count %f', count))
	table.insert(body, string.format('latency_sum %f', sum))
	writer(req, table.concat(body,'\n'), 'text/plain; version=0.0.4')
end

function M.init(conf)
	conf = conf or {}
	conf.serve = serve
	return conf
	
end

return M