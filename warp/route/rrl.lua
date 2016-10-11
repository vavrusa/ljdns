local dns = require('dns')
local ffi = require('ffi')
local lru = require('resty.lrucache')

local M = {}

local bucket_t = ffi.typeof('struct { uint32_t expire; uint16_t tok; uint16_t flags; }')

-- Response classes
local rc = {
    POSITIVE = 0,
	NXDOMAIN = 1,
	NODATA   = 2,
	BAD      = 3,
	WILDCARD = 4,
	ANY      = 5,
	LARGE    = 6,
	DNSSEC   = 7,
}
local rcn = dns.utils.itable(rc, true)


-- By QTYPE
local by_qtype = {
	[dns.type.ANY] = rc.ANY,
	[dns.type.RRSIG] = rc.DNSSEC,
	[dns.type.DNSKEY] = rc.DNSSEC,
	[dns.type.DS] = rc.DNSSEC,
	[dns.type.CDS] = rc.DNSSEC,
	[dns.type.CDNSKEY] = rc.DNSSEC,
}

local function rclass(req)
	local rcode = req.answer:rcode()
	local soa = req.soa and req.soa:owner() or req.qname
	-- Set class based on specific RCODE
	if rcode == dns.rcode.NXDOMAIN then
		return rc.NXDOMAIN, soa
	elseif rcode ~= dns.rcode.NOERROR then
		return rc.BAD, soa
	end
	if req.wildcard then
		return rc.WILDCARD, soa
	end
	-- Class based on query type
	local cls = by_qtype[req.qtype]
	if cls then return cls, req.qname end
	-- Classify oversize responses
	if req.answer.size > 512 then
		return rc.LARGE, req.qname
	end
	-- Classify empty responses
	if req.answer:empty() then
		return rc.NODATA, req.qname
	end
	return 0, req.qname
end

local function key(req, cls, name)
	-- Add imputed source address
	local src, n = req.addr, 0
	if src then
		if type(src) ~= 'string' then
			src = src.addr
		end
		n = #src
		if n == 4 then
			src = ffi.string(src, 3) -- /24
		elseif n == 16 then
			src = ffi.string(src, 7) -- /56
		end
	end
	return string.format('%d.%s.%s', cls, name, src or ''), src, n
end

local function ratelimit(self, req)
	if math.random() < self.slip then
		req.answer:tc(true)
		req.query:toanswer(req.answer)
		table.clear(req.authority)
		table.clear(req.additional)
	else
		req.answer.size = 0 -- Drop the request
	end
end

local function complete(self, req, writer)
	if req.xfer or req.is_tcp then return end
	-- Classify based on response contents
	local cls, name = rclass(req)
	name = name and name:towire() or ''
	-- Get response bucket
	local k, src, slen = key(req, cls, name)
	local b = self.lru:get(k)
	local now = ffi.cast('uint32_t', req.now)
	-- Start rate limiting (no bucket)
	if not b then
		self.lru:set(k, bucket_t(now + 1, self.rate))
	-- Resume rate limiting (bucket is expired)
	elseif b.expire < req.now then
		b.tok = self.rate
		b.expire = now + 1
	-- Continue rate limiting (bucket is active)
	else
		if b.tok == 0 then
			-- Log if not ongoing
			if b.flags == 0 then
				local pad = string.rep('\x00', slen-#src)
				req:vlog('ratelimit begin, class: %s, zone: %s, source: %s',
				        rcn[cls], dns.dname(name), dns.utils.inaddr(src..pad).addr)
				b.flags = 1
			end
			return ratelimit(self, req)
		else
			b.tok = b.tok - 1
		end
	end
end

function M.init(conf)
	conf = conf or {}
	conf.slip = conf.slip or 0.5
	conf.rate = conf.rate or 20
	conf.size = conf.size or 100000
	conf.lru = lru.new(conf.size)
	conf.serve = function () end
	conf.complete = complete
	return conf
	
end

return M