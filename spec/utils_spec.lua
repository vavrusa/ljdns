describe('utils', function()
	local dns, utils = require('dns'), require('dns.utils')

	it('compares domain names canonically', function ()
		local names = {
			'example',
			'a.example',
			'yljkjljk.a.example',
			'z.a.example',
			'zabc.a.example',
			'z.example',
			'\001.z.example',
			'*.z.example',
			'\200.z.example',
		}
		for i = 1, #names do
			names[i] = dns.dname.parse(names[i])
		end
		for i = 1, #names - 1 do
			assert.truthy(utils.dnamecmp(names[i], names[i + 1]) < 0)
		end
	end)

	it('parses addresses', function ()
		-- Test raw IPv4
		local ip = utils.inaddr('\x7f\x00\x00\x01', 53)
		assert.truthy(ip)
		assert.same('127.0.0.1', tostring(ip.addr))
		assert.same(53, ip.port)
		-- Test raw IPv6
		ip = utils.inaddr('\xfe\x80'..string.rep('\x00', 13)..'\x01', 53)
		assert.same('fe80::1', tostring(ip.addr))
		assert.same(53, ip.port)
		-- Test malformed input
		ip = utils.inaddr('abc')
		assert.falsy(ip)
	end)
end)