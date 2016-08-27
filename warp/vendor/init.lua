local M = {}

-- Compatibility environment
local modenv = {
	moduledir = 'warp/vendor',
	log = function () end,
	worker = { id = 0 },
	stats = {},
	hostname = function ()
		return io.popen('/bin/hostname'):read('*a'):match('[^\n]+')
	end,
	modules = {
		load = function (pkg) return M.new(pkg) end,
	},
	event = {
		after = function () end, -- NYI
	},
	map = function (f)
		f = assert(loadstring('return '..f))
		setfenv(f, getfenv(2))
		local ok, r = pcall(f)
		return {r}
	end,
	tojson = require('cjson').encode,
}
modenv.require = function (pkg)
	local env = getfenv(2)
	local m = package.loaders[2](string.format('warp.vendor.%s.%s', env.modname, pkg))
	if type(m) == 'function' then
		setfenv(m, env)
		return m()
	end
	return require(pkg)
end

-- Connector to jail environment
M.env = modenv

-- Load compatibility module
function M.new(mod, env)
	-- Update environment
	env = setmetatable(env or {}, {
		__index = function (t, k) return rawget(t, k) or modenv[k] or _G[k] end
	})
	env.modname = mod
	-- Load the vendored module
	local m = package.loaders[2](string.format('warp.vendor.%s.%s', env.modname, mod))
	if type(m) ~= 'function' then return nil, m end
	-- Set environment and load
	setfenv(m, env) m = m()
	env[mod] = m
	return m
end

return M