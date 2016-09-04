return setmetatable({}, {
	__index = function (t, k)
		return require('warp.route.' .. k)
	end
})