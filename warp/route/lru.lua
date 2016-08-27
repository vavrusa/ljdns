local ffi, lru, dns = require('ffi'), require('lru'), require('dns')

local M = {}

local function key(query)
	local qname = query:qname()
	local dobit = dns.edns.dobit(query.opt) and 1 or 0
	return string.format('%s.%d%d', qname:towire(query.qname_size), query:qtype(), dobit)
end

local function add(dst, section, ttl, copy)
	local count = 0
	for _, rr in ipairs(section) do
		rr = copy and rr:copy() or rr
		ttl = math.min(rr:ttl(), ttl)
		table.insert(dst, rr)
		count = count + 1
	end
	return ttl, count
end

local function serve(self, req)
	if req.nocache or req.xfer then return end
	local k = key(req.query)
	local val = self.cache:get(k)
	-- Purge stale records
	if not val then
		req.stats['cache.miss'] = (req.stats['cache.miss'] or 0) + 1
		return
	end
	if req.now > val[1] then
		req.stats['cache.delete'] = (req.stats['cache.delete'] or 0) + 1
		self.cache:delete(k)
		return
	end
	-- Retrieve entry from cache
	local rrs = val[5]
	local base = 0
	for i = 1, val[2] do req.answer:put(rrs[base + i], true) end
	base = base + val[2]
	for i = 1, val[3] do table.insert(req.authority, rrs[base + i]) end
	base = base + val[3]
	for i = 1, val[4] do table.insert(req.additional, rrs[base + i]) end
	-- Restore RCODE and flags
	req.answer:rcode(val[6])
	local aa, dobit = val[6], val[7]
	req.answer:aa(req.opt, aa)
	dns.edns.dobit(req.opt, dobit)
	-- Do not cache the result
	req.nocache = true
	req.stats['cache.hit'] = (req.stats['cache.hit'] or 0) + 1
	return false
end

local function complete(self, req)
	if req.nocache or req.xfer then return end
	local rrs, ttl, an, ns, ar = {}, 0xffffffff
	ttl, an = add(rrs, req.answer, ttl, true)
	ttl, ns = add(rrs, req.authority, ttl)
	ttl, ar = add(rrs, req.additional, ttl)
	-- Cache answer if it's not empty
	if an + ns + ar > 0 and ttl > 0 then
		local flags = dns.edns.dobit(req.answer.opt)
		local entry = {req.now + ttl, an, ns, ar, rrs, req.answer:rcode(), req.answer:aa(), flags}
		self.cache:set(key(req.query), entry)
	end
end

function M.init(conf)
	conf = conf or {}
	local cache = lru.new(conf.size or 100000)
	return {cache=cache, serve=serve, complete=complete}
end

return M