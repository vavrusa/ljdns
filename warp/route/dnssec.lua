local dns, dnssec, go = require('dns'), require('dns.dnssec'), require('dns.nbio')
local ffi = require('ffi')

local M = {}

-- Make sure the signer if ready for signing
local function check_signer(self, req)
	if not self.next_time or req.now < self.next_time then return end
	local keyset = self.keyset
	keyset:action(self.next_action, req.now)
	-- Update keyset and signer
	self.zsk, self.ksk, self.rolling = keyset:zsk(), keyset:ksk(), keyset:rolling()
	self.signer = dnssec.signer(self.zsk)
	-- Plan next action
	self.next_time, self.next_action = keyset:plan(req.now)
end

-- Sign records in section
local function sign_section(self, req, section, writer)
	local signer = self.signer
	local zone_name = req.soa and req.soa:owner()
	-- Merge/dedup records before signing
	local dedup, cloned = nil, false
	-- Generate signatures for answers
	local rrsigs = {}
	for _, rr in ipairs(section) do
		if rr:type() ~= dns.type.RRSIG then
			if not dedup then -- First record
				dedup, cloned = rr, false
			elseif not dedup:equals(rr) then -- Different record
				table.insert(rrsigs, signer:sign(dedup))
				dedup, cloned = rr, false
			else -- Record matches, merge it with previous
				if not cloned then
					dedup, cloned = dedup:copy(), true
				end
				dedup:merge(rr)
			end
		end
	end
	if dedup then
		local signer = self.signer		
		-- Sign DNSKEY with KSK
		if dedup:type() == dns.type.DNSKEY then
			signer = dnssec.signer(self.ksk)
		end
		table.insert(rrsigs, signer:sign(dedup, nil, req.now, zone_name))
	end
	-- Write signatures to packet
	for _, rr in ipairs(rrsigs) do
		writer(section, rr)
	end
end

-- Authenticated denial of existence
local function denial(self, req, nxdomain)
	-- Fetch MINTTL from authority SOA
	local ttl = req.soa and dns.rdata.soa_minttl(req.soa:rdata(0)) or 0
	local nsec = dnssec.denial(req.query:qname(), req.query:qtype(), ttl, nxdomain)
	-- Add NSEC to authority
	table.insert(req.authority, nsec)
end

-- Return DNSKEY for this zone
local function dnskey(self, req, zone)
	-- Add active/published ZSK
	local rr = dns.rrset(zone, dns.type.DNSKEY)
	           :add(self.zsk:rdata(), req.soa:ttl())
	req.answer:put(rr)
	if self.rolling then
		rr = dns.rrset(zone, dns.type.DNSKEY)
			:add(self.rolling:rdata(), req.soa:ttl())
		req.answer:put(rr)
	end
	-- Add KSK
	if self.ksk then
		rr = dns.rrset(zone, dns.type.DNSKEY)
			:add(self.ksk:rdata(), req.soa:ttl())
		req.answer:put(rr)
	end
	-- Remove authority SOA (if present)
	local soa = table.remove(req.authority)
	if soa and soa:type() ~= dns.type.SOA then
		table.insert(req.authority, soa)
	end
end

-- Sign records in the answer
local function serve(self, req, writer)
	-- Check if we DNSSEC is requested
	if req.xfer or not dns.edns.dobit(req.query.opt) then
		return
	end
	-- Check signer
	check_signer(self, req)
	local nxdomain = (req.answer:rcode() == dns.rcode.NXDOMAIN)
	local qname, qtype = req.query:qname(), req.query:qtype()
	-- If this is DNSKEY query, answer it
	if qtype == dns.type.DNSKEY and req.soa and qname:equals(req.soa:owner()) then
		dnskey(self, req, qname)
	elseif nxdomain or req.answer:empty() then
		-- If NOERROR or NXDOMAIN, generate denial
		denial(self, req, nxdomain)
		-- Turn NXDOMAIN into NODATA
		if nxdomain then req.answer:rcode(dns.rcode.NOERROR) end
	end
	sign_section(self, req, req.answer, req.answer.put)
	sign_section(self, req, req.authority, table.insert)
	sign_section(self, req, req.additional, table.insert)
	-- Set DNSSEC OK
	dns.edns.dobit(req.opt, true)
	return true
end

-- Set ZSK for record signing
function M.init(conf)
	conf = conf or {}
	local o = conf.options or {}
	local context = {serve=serve}
	-- If keyfile is not specified, generate it
	if conf.key then
		local key = dnssec.key()
		key:algo(dnssec.algo[conf.algo] or dnssec.algo.ecdsa_p256_sha256)
		key:privkey(key)
		context.manual = true
		context.zsk = key
		context.signer = dnssec.signer(key)
		assert(key:can_sign(), 'given key cannot be used for signing')
	else
		-- Set KASP defaults if not configured
		conf.kasp = conf.kasp or 'kasp'
		conf.keystore = conf.keystore or 'default'
		conf.policy = conf.policy or 'default'
		conf.keyset = conf.keyset or 'default'
		o.policy = o.policy or {}
		o.policy.keystore = conf.keystore
		-- Set/update KASP, keystore and keyset
		local kasp = assert(dnssec.kasp(conf.kasp))
		local keystore = assert(kasp:keystore(conf.keystore, o.keystore or {}))
		local policy = assert(kasp:policy(conf.policy, o.policy))
		local keyset = assert(kasp:keyset(conf.keyset, {policy=conf.policy}))
		context.keyset = keyset
		-- Start KASP in manual/automatic mode
		if o.manual then
			local zsk, ksk = keyset:zsk(), keyset:ksk()
			if not zsk then zsk = keyset:generate(false, nil, true) end
			if not ksk then ksk = keyset:generate(true, nil, true) end
			context.zsk, context.ksk = zsk, ksk
			context.signer = dnssec.signer(zsk)
			context.manual = true
		else
			-- Plan next keyset action
			local now = os.time()
			local time, action = keyset:plan(now)
			context.next_time, context.next_action = time, action
			context.zsk, context.ksk = keyset:zsk(), keyset:ksk()
			context.signer = dnssec.signer(context.zsk)
		end
	end
	-- Return signer context
	return context
	
end

return M