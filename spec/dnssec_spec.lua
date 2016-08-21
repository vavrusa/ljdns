-- Pack table of bytes to string
describe('dnssec', function()
	local dns = require('dns')
	local dnssec = require('dns.dnssec')

	for _, sample_key in pairs(sample_keys) do
		it('creates keys for '..sample_key.name, function()
			local key = dnssec.key()
			assert.truthy(key)
			assert.falsy(key:can_sign())
			assert.falsy(key:can_verify())
			-- Set public key for verification
			key:algo(sample_key.algorithm)
			assert.truthy(key:pubkey(sample_key.public_key))
			assert.truthy(key:can_verify())
			assert.same(sample_key.algorithm, key:algo())
			assert.same(sample_key.keytag, key:tag())
			-- Set private key for signing
			assert.truthy(key:privkey(sample_key.pem))
			assert.truthy(key:can_sign())
		end)
	end

	for _, sample_key in pairs(sample_keys) do
		it('can sign/verify '..sample_key.name, function()
			local key = dnssec.key()
			key:algo(sample_key.algorithm)
			key:privkey(sample_key.pem)
			local signer, err = dnssec.signer(key)
			assert.truthy(signer, err)
			-- Verify input signature
			assert.truthy(signer:add(sample_key.input))
			assert.truthy(signer:verify(sample_key.output))
			-- Sign again and verify
			local signature = signer:get()
			assert.truthy(signer:verify(signature))
			-- Sign RRSet
			local rr = dns.rrset('\7example', dns.type.A)
			rr:add('\1\2\3\4', 60)
			rr:add('\4\3\2\1')
			local rrsig = signer:sign(rr)
			-- Verify generated signature
			assert.truthy(signer:verify(rr, rrsig))
		end)
	end
end)
