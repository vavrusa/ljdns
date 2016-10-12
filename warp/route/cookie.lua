local dns = require('dns')
local ffi = require('ffi')

local M = {}

local function reseed(self)
	self.secret_old = self.secret
	self.expire_old = os.time() + self.retain
	self.secret = ffi.cast('uint64_t', math.random(0, 0xffffffffffffffff))
	self.expire = os.time() + self.rollover - (self.rollover * math.random() * 0.4)
end

local hash_buf, hash_val = ffi.new('uint64_t [?]', 4), ffi.new('uint64_t [2]')
local function hash(secret, req, cookie)
	-- Get address bytes
	local src = req.addr
	if type(src) ~= 'string' then
		src = ffi.string(src.addr, src.len)
	end
	-- Mix in source address and secret
	local len = #src + 8 + 8
	assert(len <= 32)
	hash_buf[0] = secret
	ffi.copy(hash_buf + 1, src)
	ffi.copy(hash_buf + 2, cookie, 8)
	dns.utils.hash128(hash_buf, len, hash_val)
	-- Truncate to upper 64bits
	return hash_val[1]
end

local function compute(self, req, cookie, secret)
	if req.now > self.expire then
		req:log('cookie reseed secret')
		reseed(self)
	end
	secret = secret or self.secret
	return hash(secret, req, cookie)
end

local pair_buf = ffi.new('uint64_t [2]')
local function append(self, req, client, server)
	server = server or compute(self, req, client)
	req:vlog('cookie appending: %s', server)
	-- Assemble cookie pair
	ffi.copy(pair_buf, client, 8)
	pair_buf[1] = server
	-- Add COOKIE option to response
	dns.edns.option(req.opt, dns.option.COOKIE, pair_buf, ffi.sizeof(pair_buf))
end

local function begin(self, req, client)
	req.stats.cookie_want = (req.stats.cookie_want or 0) + 1
	return append(self, req, client)
end

local function fail(self, req)
	req:vlog('cookie is invalid')
	-- Append BADCOOKIE if on UDP or strict validation
	if not req.is_tcp or self.strict then
		req.stats.cookie_bad = (req.stats.cookie_bad or 0) + 1
		req.answer:rcode(dns.rcode.BADCOOKIE)
		req.stats.cookie_drop = (req.stats.cookie_drop or 0) + 1
		return false -- Bail
	end
end

local function track(self, req, cookie)
	local sc = compute(self, req, cookie)
	ffi.copy(pair_buf, cookie:sub(8+1))
	req:vlog('cookie verify: %s ~ %s (current)', pair_buf[0], sc)
	-- Compare against current/old server cookie
	local current_cookie = sc
	if pair_buf[0] ~= sc then
		if not self.secret_old or req.now > self.expire_old then
			return fail(self, req)
		end
		-- Check old server cookie before failing
		sc = compute(self, req, cookie, self.secret_old)
		req:vlog('cookie verify: %s ~ %s (old)', pair_buf[0], sc)
		if pair_buf[0] ~= sc then
			return fail(self, req)
		end
	end
	-- Established session between client and server
	req.stats.cookie_ok = (req.stats.cookie_ok or 0) + 1
	req.session = sc
	-- Add current COOKIE option to a response
	append(self, req, cookie, current_cookie)
end

local function bad(self, req, cookie)
	req:vlog('malformed client cookie')
	req.answer:rcode(dns.rcode.FORMERR)
	req.stats.cookie_formerr = (req.stats.cookie_formerr or 0) + 1
	return false -- Bail
end

local function serve(self, req, writer)
	-- Find COOKIE option and verify it
	local cookie = dns.edns.option(req.query.opt, dns.option.COOKIE)
	if not cookie then return end
	-- (1) Only client cookie
	local len = #cookie
	if len == 8 then
		return begin(self, req, cookie)
	-- (3-5) Valid cookie (implemented 64 + 64 bit cookie pair)
	elseif len == 16 then
		return track(self, req, cookie)
	-- (2) Malformed cookie
	else
		return bad(self, req, cookie)
	end
end

function M.init(conf)
	conf = conf or {}
	conf.rollover = conf.rollover and math.min(conf.rollover, 36*24*3600) or 26*3600
	conf.retain = conf.retain and math.min(conf.retain, 300) or 150
	conf.serve = serve
	reseed(conf)
	return conf
end

return M