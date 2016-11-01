local dns, rrparser, go = require('dns'), require('dns.rrparser'), require('dns.nbio')
local now = require('dns.nbio').now
local ffi = require('ffi')
local log = require('warp.init').log

local M = {}

local function log_event(msg, ...)
	log(nil, 'info', msg, ...)
end

local function log_error(msg, ...)
	log(nil, 'error', msg, ...)
end

-- Pooled objects
local txnpool, cached_rr = {}, ffi.gc(dns.rrset(), dns.rrset.init)

-- Add RR to packet and send it out if it's full
local function add_rr(req, writer, rr)
	if not req.answer:put(rr) then
		assert(writer(req, req.answer, req.addr))
		req.msg:toanswer(req.answer)
		req.answer:aa(true)
		req.answer:put(rr)
		return 1
	end
	return 0
end

local function positive(self, req, writer, rr)
	add_rr(req, writer, rr:copy())
end

local function negative(self, req, writer, rr, txn)
	table.insert(req.authority, req.soa)
end

local function answer(self, req, writer, rr, txn, qname)
	-- Find name encloser in given zone
	local match, cut, wildcard = self.store:match(txn, req.soa, qname, req.qtype, rr)
	if cut then -- Name is below a zone cut
		req:vlog('name below zone cut %s, sending referral', cut:owner())
		cut = cut:copy()
		table.insert(req.authority, cut)
		self.store:addglue(txn, cut, rr, req.additional)
		return
	end
	-- Zone is authoritative for this name
	req.answer:aa(true)
	-- Encloser equal to QNAME, or covered by a wildcard
	if match then
		local covered, owner = match:type(), match:owner()
		local is_cname = (covered == dns.type.CNAME)
		if covered == req.qtype or is_cname then
			if wildcard or qname:equals(owner) then
				positive(self, req, writer, match)
				-- Chase CNAME chain
				if is_cname and req.qtype ~= dns.type.CNAME then
					local target = ffi.cast('knot_dname_t *', match:rdata(0))
					if target:within(req.soa:owner()) then
						req:vlog('chasing CNAME %s', target)
						answer(self, req, writer, rr, txn, target[0])
					end
				end
				return
			end
		end
	end
	-- No match for given name
	req:vlog('name not exists')
	return (negative(self, req, writer, rr))
end

-- Answer query from zonefile
local function serve(self, req, writer)
	if req.answer:aa() then return end
	-- Fetch an r-o transaction
	local txn = table.remove(txnpool)
	if txn then
		txn:renew()
	else
		txn = self.store:txn(true)
	end
	-- Find zone apex for given name
	local rr = cached_rr
	local soa = self.store:zone(txn, req.qname, rr)
	if not soa then
		req:vlog('%s: refused (no zone found)', req.qname)
		req.answer:rcode(dns.rcode.REFUSED)
		txn:reset()
		table.insert(txnpool, txn)
		return -- No file to process, bail
	end
	-- Set zone authority and build answer
	req.soa = soa:copy()
	answer(self, req, writer, rr, txn, req.qname)
	txn:reset()
	table.insert(txnpool, txn)
	return
end

local function update(store, keys, txn, rr)
	local key = assert(store:set(txn, rr))
	keys[key] = nil
	rr:clear()
	return 1
end

local function sync_file(self, txn, zone, path)
	-- Open parser and start new txn
	local parser = assert(rrparser.new())
	assert(parser:open(path))
	-- Get current version of given zone
	local current, serial, current_keys
	do
		local rr = self.store:get(txn, zone, dns.type.SOA)
		if rr then
			current = dns.rdata.soa_serial(rr:rdata(0))
		end
	end
	-- Start parsing the source file
	local updated, deleted, start = 0, 0, now()
	local rr = dns.rrset(nil, 0)
	while parser:parse() do
		-- Compare SOA serial to current
		if parser.r_type == dns.type.SOA then
			serial = dns.rdata.soa_serial(parser.r_data)
			-- SOA serial unchanged, abort
			if current and serial == current then
				log_event('zone: %s, status: unchanged (serial: %u)', zone, current)
				parser:reset()
				return
			else
				-- Get all keys present in current version of a zone
				log_event('zone: %s, status: syncing (serial: %u -> %u)', zone, current or 0, serial)
				current_keys = self.store:scan(txn, zone)
			end
		end
		-- Merge records into RR sets
		if rr:empty() then
			rr:init(parser.r_owner, parser.r_type)
		elseif rr:type() ~= parser.r_type or not rr:owner():equals(parser.r_owner, parser.r_owner_length) then
			-- Store complete RR set and start new
			updated = updated + update(self.store, current_keys, txn, rr)
			rr:init(parser.r_owner, parser.r_type)
		end
		rr:add(parser.r_data, parser.r_ttl, parser.r_data_length)
	end
	-- Insert last RR set
	if not rr:empty() then
		updated = updated + update(self.store, current_keys, txn, rr)
	end
	parser:reset()
	-- Delete keys that do not exist in new version
	if current_keys then
		for k, _ in pairs(current_keys) do
			self.store:del(txn, k)
			deleted = deleted + 1
		end
	end
	log_event('zone: %s, status: done (updated: %u, removed: %u, time: %.03fs)',
		zone, updated, deleted, now() - start)
end

local function loadzonefile(self, path)
	local zone = dns.dname.parse(path:match('([^/]+).zone$'))
	local txn = self.store:txn()
	local ok, err = pcall(sync_file, self, txn, zone, path)
	if ok then
		ok, err = txn:commit()
		if not ok then
			log_error('zone: %s, status: failed to commit, error: %s', zone, err)
		end
	else
		txn:abort()
		log_error('zone: %s, status: failed, error: %s', zone, err)
	end


	collectgarbage()
end

-- Synchronise with backing store
local function sync(self)
	if not self.source then return end
	-- File source backend
	if dns.utils.isdir(self.source) then
		for _,v in ipairs(dns.utils.ls(self.source)) do
			if v:find('.zone$') then
				loadzonefile(self, self.source .. '/' .. v)
			end
		end
	else
		loadzonefile(self, self.source)
	end
end

-- Public API
local api = {
	sync = function(self, req, writer)
		if req.method ~= 'POST' then
			return nil, 501
		end
		sync(self)
	end
}

-- Module initialiser
function M.init(conf)
	conf = conf or {}
	conf.path = conf.path or '.'
	conf.store = conf.store or 'lmdb'
	-- Check if store is available and open it
	local ok, store
	if type(conf.store) == 'string' then
		ok, store = pcall(require, 'warp.store.' .. conf.store)
	else
		ok, store = true, conf.store
	end
	assert(ok, string.format('store "%s" is not available: %s', conf.store, store))
	conf.store = assert(store.open(conf))
	-- Synchronise
	sync(conf)
	-- Route API
	conf.name = 'auth'
	conf.serve = serve
	conf.api = api
	return conf
end

return M