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

function M.get(self, c, k)
	local r = getconn(self)
	local v, err = r:get(k)
	release(r)
	return v, err
end

function M.txn(self)
	return getconn(self.conf)
end

function M.commit(self, txn)
	release(txn)
end

function M.init(conf)
	conf = conf or {}
	conf.ttl  = conf.ttl or 30
	conf.host = conf.host or '127.0.0.1'
	conf.port = conf.port or 6379
	conf.timeout = conf.timeout or 1000
	if conf.host:find '/' then conf.port = nil end
	-- Implement store interface
	conf.get = M.get
	conf.txn = M.txn
	conf.commit = M.commit
	return conf
end

return M