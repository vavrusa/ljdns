local lru = require('warp.route.lru')
local redis = require('resty.redis')
local ffi = require('ffi')

local M = {}

-- Pool redis objects
local pool = {}
local function getconn(conf)
	local r = table.remove(pool)
	if r then return r end
	local r = redis:new()
	r:set_timeout(conf.timeout)
	local ok, err = r:connect(conf.host, conf.port)
	if not ok then
		error('failed to connect: ' .. err)
	end
	return r
end
local function release(c)
	if #pool < 100 then table.insert(pool, c) end
end

local function serve(self, req)
	if req.nocache or req.xfer then return end
	local k = lru.key(req.query)
	-- Attempt to retrieve the key
	local r = getconn(self.conf)
	local v = r:get(k)
	if not v then
		req.stats['cache.miss'] = (req.stats['cache.miss'] or 0) + 1
		release(r)
		return
	end
	-- Copy cached packet
	local vlen = #v
	assert(req.answer.max_size >= vlen)
	ffi.copy(req.answer.wire, v, vlen)
	req.answer.size = vlen
	req.answer.parsed = vlen
	-- Restore message ID
	req.answer:id(req.query:id())
	req.stats['cache.hit'] = (req.stats['cache.hit'] or 0) + 1
	release(r)
	return false
end

local function complete(self, req)
	if req.nocache or req.xfer then return end
	local k = lru.key(req.query)
	local r = getconn(self.conf)
	r:set(k, req.answer:towire())
	r:expire(k, self.conf.ttl)
	release(r)
end

function M.init(conf, ct)
	conf = conf or {}
	conf.ttl  = conf.ttl or 30
	conf.host = conf.host or '127.0.0.1'
	conf.port = conf.port or 6379
	conf.timeout = conf.timeout or 1000
	if conf.host:find '/' then conf.port = nil end
	return {conf=conf, serve=serve, complete=complete}
end

return M