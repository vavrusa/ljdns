local S = require('syscall')
-- Pack table of bytes to string
describe('dnssec', function()
	local dns = require('dns')
	local dnssec = require('dns.dnssec')
	local tmpdir = nil

	setup(function()
		tmpdir = os.getenv('TMPDIR') or S.getcwd()
		tmpdir = tmpdir .. '/.test_dnssec'
		S.util.rm(tmpdir)
		S.mkdir(tmpdir, 'rwxu')
	end)

	teardown(function()
		S.util.rm(tmpdir)
		collectgarbage()
	end)

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

	it('does authenticated denial of existence', function ()
		local owner = dns.dname('\7example')
		assert.truthy(dnssec.denial(owner, dns.type.A))
		assert.truthy(dnssec.denial(owner, dns.type.A, true))
	end)

	describe('KASP', function ()
		local kasp = dnssec.kasp(tmpdir)
		assert.truthy(kasp)
		it('create policies', function ()
			local policy = kasp:policy('ecdsa')
			assert.falsy(policy, 'policy shouldnt exist yet')
			-- Create invalid policy
			policy = kasp:policy('ecdsa', {
				algorithm = 999,
				soa_minimal_ttl = 60,
			})
			assert.falsy(policy, 'invalid policy created')
			-- Create a valid policy
			policy = kasp:policy('ecdsa', {
				algorithm = 'ecdsa_p256_sha256',
				soa_minimal_ttl = 60,
			})
			assert.truthy(policy, 'valid policy not created')
			assert.same(60, policy.soa_minimal_ttl)
			assert.same(dnssec.algo.ecdsa_p256_sha256, policy.algorithm)
			-- Try to remove and fetch policy
			assert.truthy(kasp:policy('ecdsa', false), 'policy not removed')
			assert.falsy(kasp:policy('ecdsa'), 'policy shouldnt exist')
		end)
		it('open key stores', function ()
			local policy = kasp:policy('ecdsa', {
				algorithm = 'ecdsa_p256_sha256',
				soa_minimal_ttl = 60,
			})
			local keys = kasp:keystore(policy)
			assert.truthy(keys, 'didnt open a keystore for policy')
			-- Generate some keys
			local ksk, key_id = keys:generate(policy, true)
			assert.truthy(ksk, 'didnt create ksk')
			assert.truthy(key_id, 'didnt generate key id')
			-- Retrieve keys
			for _, id in ipairs(keys) do
				local key = keys:get(policy, id)
				assert.truthy(key, 'reopened key')
				assert.same(key_id, id)
			end
			-- Remove keys
			assert.truthy(keys:del(key_id))
			assert.falsy(keys:get(policy, key_id), 'getting removed key')
			-- Create alternate keystores
			local keys, err = kasp:keystore('another', {
				backend = 'pkcs8',
				config = 'keys2'
			})
			assert.truthy(keys, 'didnt create another keystore: ' .. (err or ''))
			local lib = os.getenv('SOFTHSM_LIB')
			if lib then
				local keys, err = kasp:keystore('softhsm', {
					backend = 'pkcs11',
					config = 'pkcs11:token=dnssec;pin-value=1234 ' .. lib, 
				})
				assert.truthy(keys, 'didnt create PKCS11 keystore: ' .. (err or ''))
			end
		end)
		it('create keysets', function ()
			local keyset, err = kasp:keyset('example', {
				policy = 'ecdsa',
			})
			assert.truthy(keyset, err)
			local policy = kasp:policy('ecdsa')
			-- Manually generate additional KSK
			local ksk, key_id = keyset:generate(true)
			assert.truthy(ksk, 'didnt generate keyset key')
			assert.truthy(ksk:can_sign(), 'generated key that cannot sign')
			-- Walk keyset
			for _, z in keyset:keys() do
				assert.truthy(z.id, 'doesnt have unique key id')
			end
			-- Perform key rollover: initialise
			local now = os.time()
			local time, action = keyset:plan(now)
			assert.same(now, time, 'initial signing not now')
			assert.same(dnssec.action.ZSK_INIT, action, 'didnt schedule initial signing')
			keyset:action(action, time)
			-- Perform key rollover: publish keys
			local time, action = keyset:plan(now)
			assert.same(now + policy.zsk_lifetime, time, 'didnt schedule rollover start in the future')
			assert.same(dnssec.action.ZSK_PUBLISH, action, 'didnt schedule rollover start')
			now = time
			keyset:action(action, time)
			-- Perform key rollover: key published, start resigning
			local time, action = keyset:plan(now)
			assert.same(dnssec.action.ZSK_RESIGN, action, 'didnt schedule rollover resign')
			assert.same(now + policy.propagation_delay + policy.dnskey_ttl, time, 'didnt schedule rollover resign in the future')
			now = time
			keyset:action(action, time)
			-- Perform key rollover: resigned, start retiring old key
			local time, action = keyset:plan(now)
			assert.same(dnssec.action.ZSK_RETIRE, action, 'didnt schedule retire of zsk')
			assert.same(now + policy.propagation_delay + policy.zone_maximal_ttl, time, 'didnt schedule rollover reture in the future')
			now = time
			keyset:action(action, time)
			-- Perform key rollover: rollover complete, start new
			local time, action = keyset:plan(now)
			assert.same(dnssec.action.ZSK_PUBLISH, action, 'didnt finish rollover')
		end)
	end)
end)
