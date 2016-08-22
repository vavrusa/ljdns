local dns, dnssec = require('dns'), require('dns.dnssec')
local ffi = require('ffi')

local M = {}

-- Sign records in section
local function sign_section(self, section, writer)
	local signer = self.signer
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
	if dedup then table.insert(rrsigs, signer:sign(dedup)) end
	-- Write signatures to packet
	for _, rr in ipairs(rrsigs) do
		writer(section, rr)
	end
end

-- Authenticated denial of existence
local function denial(self, req, nxdomain)
	local ttl = 0
	-- Fetch MINTTL from authority SOA
	local soa = req.authority[1]
	if soa and  soa:type() == dns.type.SOA then
		ttl = dns.rdata.soa_minttl(soa:rdata(0))
	end
	local nsec = dnssec.denial(req.query:qname(), req.query:qtype(), ttl, nxdomain)
	-- Add NSEC to authority
	table.insert(req.authority, nsec)
end

-- Check if we DNSSEC is requested
local function accept(self, req)
	return not req.xfer and req.query.opt ~= nil and dns.edns.dobit(req.query.opt)
end

-- Sign records in the answer
local function serve(self, req, writer)
	-- If NOERROR or NXDOMAIN, generate denial
	local nxdomain = (req.answer:rcode() == dns.rcode.NXDOMAIN)
	if nxdomain or req.answer:empty() then
		denial(self, req, nxdomain)
		-- Turn NXDOMAIN into NODATA
		if nxdomain then req.answer:rcode(dns.rcode.NOERROR) end
	end
	sign_section(self, req.answer, req.answer.put)
	sign_section(self, req.authority, table.insert)
	sign_section(self, req.additional, table.insert)
	return true
end

-- Set ZSK for record signing
function M.init(self, conf)
	local key = dnssec.key()
	-- Set key algorithm
	key:algo(dnssec.algo[conf.algo] or dnssec.algo.ecdsa_p256_sha256)
	-- If keyfile is not specified, generate it
	if not conf.key then
		require('spec.helper')
		key:privkey(sample_keys.ecdsa.pem) -- TODO
	end
	-- Return signer context
	assert(key:can_sign(), 'given key cannot be used for signing')
	local signer = dnssec.signer(key)
	return {key=key, signer=signer, serve=serve, accept=accept}
	
end

return M