local http = require('resty.http')

local M = {}

function M.get(self, c, k)
	local ok, err = c:connect(self.host, self.port)
	if not ok then error(err) end
	local res, err = c:request {
		path = self.url:format(k),
	}

	if err or res.status ~= 200 or not res.has_body then
		res = res or {status=500, reason=err}
		return nil, err or res.status
	end

	return res:read_body()
end

function M.txn(self)
	return http.new()
end

function M.commit(self, txn)
end

function M.init(conf)
	conf.host = conf.host or '127.0.0.1'
	conf.port = conf.port or 2379
	conf.timeout = conf.timeout or 100
	conf.url = '/v2/keys' .. conf.prefix .. '/%s?recursive=true'
	if conf.host:find '/' then
		conf.port = nil
	end
	-- Implement store interface
	conf.get = M.get
	conf.txn = M.txn
	conf.commit = M.commit
	return conf
end

return M