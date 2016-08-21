local dns, dnssec = require('dns'), require('dns.dnssec')
local ffi = require('ffi')

local M = {}

-- Check if we DNSSEC is requested
local function accept(self, req)
	return req.query.opt ~= nil and dns.edns.dobit(req.query.opt)
end

-- Sign records in the answer
local function serve(self, req, writer)
	local answer = req.answer
	local current = answer:section()
	local records = answer:section(current)
	-- Generate signatures
	local rrsigs = {}
	for _, rr in ipairs(records) do
		if rr:type() ~= dns.type.RRSIG then
			table.insert(rrsigs, self.signer:sign(rr))
		end
	end
	-- Write signatures to packet
	for _, rr in ipairs(rrsigs) do
		answer:put(rr)
	end
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