local ffi = require('ffi')
local utils = require('dns.utils')
local dns = require('dns')
local lib = utils.clib('dnssec', {2})
assert(lib, 'libdnssec not found, install libknot >= 2.3.0')

ffi.cdef [[
/* crypto.h */
void dnssec_crypto_init(void);
void dnssec_crypto_cleanup(void);

/* error.h */
const char *dnssec_strerror(int error);

/* binary.h */
typedef struct { size_t size; uint8_t *data; } dnssec_binary_t;
int dnssec_binary_alloc(dnssec_binary_t *data, size_t size);
void dnssec_binary_free(dnssec_binary_t *binary);

/* list.h */
typedef void dnssec_list_t;
typedef void dnssec_item_t;
dnssec_item_t *dnssec_list_head(dnssec_list_t *list);
dnssec_item_t *dnssec_list_next(dnssec_list_t *list, dnssec_item_t *item);
void *dnssec_item_get(const dnssec_item_t *item);
void dnssec_list_free_full(dnssec_list_t *list, void *free_cb, void *free_ctx);
int dnssec_list_append(dnssec_list_t *list, void *data);

/* key.h */
typedef struct {} dnssec_key_t;
int dnssec_key_new(dnssec_key_t **key);
void dnssec_key_clear(dnssec_key_t *key);
void dnssec_key_free(dnssec_key_t *key);
uint16_t dnssec_key_get_keytag(dnssec_key_t *key);
const uint8_t *dnssec_key_get_dname(const dnssec_key_t *key);
int dnssec_key_set_dname(dnssec_key_t *key, const uint8_t *dname);
uint16_t dnssec_key_get_flags(const dnssec_key_t *key);
int dnssec_key_set_flags(dnssec_key_t *key, uint16_t flags);
uint8_t dnssec_key_get_protocol(const dnssec_key_t *key);
int dnssec_key_set_protocol(dnssec_key_t *key, uint8_t protocol);
uint8_t dnssec_key_get_algorithm(const dnssec_key_t *key);
int dnssec_key_set_algorithm(dnssec_key_t *key, uint8_t algorithm);
int dnssec_key_get_rdata(const dnssec_key_t *key, dnssec_binary_t *rdata);
int dnssec_key_set_rdata(dnssec_key_t *key, const dnssec_binary_t *rdata);
int dnssec_key_get_pubkey(const dnssec_key_t *key, dnssec_binary_t *pubkey);
int dnssec_key_set_pubkey(dnssec_key_t *key, const dnssec_binary_t *pubkey);
int dnssec_key_load_pkcs8(dnssec_key_t *key, const dnssec_binary_t *pem);
bool dnssec_key_can_sign(const dnssec_key_t *key);
bool dnssec_key_can_verify(const dnssec_key_t *key);

/* sign.h */
typedef void dnssec_sign_ctx_t;
typedef struct dnssec_signer { dnssec_sign_ctx_t *d[1]; uint8_t algo; uint16_t tag; };
int dnssec_sign_new(dnssec_sign_ctx_t **ctx_ptr, const dnssec_key_t *key);
void dnssec_sign_free(dnssec_sign_ctx_t *ctx);
int dnssec_sign_init(dnssec_sign_ctx_t *ctx);
int dnssec_sign_add(dnssec_sign_ctx_t *ctx, const dnssec_binary_t *data);
int dnssec_sign_write(dnssec_sign_ctx_t *ctx, dnssec_binary_t *signature);
int dnssec_sign_verify(dnssec_sign_ctx_t *ctx, const dnssec_binary_t *signature);

/* bitmap.h */
typedef void dnssec_nsec_bitmap_t;
dnssec_nsec_bitmap_t *dnssec_nsec_bitmap_new(void);
void dnssec_nsec_bitmap_clear(dnssec_nsec_bitmap_t *bitmap);
void dnssec_nsec_bitmap_free(dnssec_nsec_bitmap_t *bitmap);
void dnssec_nsec_bitmap_add(dnssec_nsec_bitmap_t *bitmap, uint16_t type);
size_t dnssec_nsec_bitmap_size(const dnssec_nsec_bitmap_t *bitmap);
void dnssec_nsec_bitmap_write(const dnssec_nsec_bitmap_t *bitmap, uint8_t *output);

/* kasp.h */
typedef int dnssec_key_algorithm_t;
typedef struct {} dnssec_kasp_t;
int dnssec_kasp_init(dnssec_kasp_t *kasp, const char *config);
void dnssec_kasp_deinit(dnssec_kasp_t *kasp);
int dnssec_kasp_init_dir(dnssec_kasp_t **kasp);
int dnssec_kasp_open(dnssec_kasp_t *kasp, const char *config);
void dnssec_kasp_close(dnssec_kasp_t *kasp);

/* kasp.h - zone/keyset */
typedef struct dnssec_kasp_key_timing {
	time_t created;
	time_t publish;
	time_t active;
	time_t retire;
	time_t remove;
} dnssec_kasp_key_timing_t;
typedef struct dnssec_kasp_key {
	char *id;
	dnssec_key_t *key;
	dnssec_kasp_key_timing_t timing;
} dnssec_kasp_key_t;
typedef struct dnssec_kasp_zone {
	const char *name;
	knot_dname_t *dname;
	const char *policy;
	void *keys;
	dnssec_binary_t nsec3_salt;
	time_t nsec3_salt_created;
} dnssec_kasp_zone_t;
dnssec_kasp_zone_t *dnssec_kasp_zone_new(const char *name);
void dnssec_kasp_zone_free(dnssec_kasp_zone_t *zone);
int dnssec_kasp_zone_load(dnssec_kasp_t *kasp, const char *name, dnssec_kasp_zone_t **zone);
int dnssec_kasp_zone_save(dnssec_kasp_t *kasp, const dnssec_kasp_zone_t *zone);
dnssec_list_t *dnssec_kasp_zone_get_keys(dnssec_kasp_zone_t *zone);
int dnssec_kasp_zone_set_policy(dnssec_kasp_zone_t *zone, const char *name);

/* kasp.h - policies */
typedef struct {
	const char *name;
	bool manual;
	const char *keystore;
	dnssec_key_algorithm_t algorithm;
	uint16_t ksk_size;
	uint16_t zsk_size;
	uint32_t dnskey_ttl;
	uint32_t zsk_lifetime;
	bool singe_type_signing;
	uint32_t rrsig_lifetime;
	uint32_t rrsig_refresh_before;
	bool nsec3_enabled;
	uint32_t nsec3_salt_lifetime;
	uint16_t nsec3_iterations;
	uint8_t nsec3_salt_length;
	uint32_t soa_minimal_ttl;
	uint32_t zone_maximal_ttl;
	uint32_t propagation_delay;
} dnssec_kasp_policy_t;
int dnssec_kasp_policy_exists(dnssec_kasp_t *kasp, const char *policy_name);
int dnssec_kasp_policy_load(dnssec_kasp_t *kasp, const char *name, dnssec_kasp_policy_t **policy);
dnssec_kasp_policy_t *dnssec_kasp_policy_new(const char *name);
void dnssec_kasp_policy_free(dnssec_kasp_policy_t *policy);
int dnssec_kasp_policy_validate(const dnssec_kasp_policy_t *policy);
void dnssec_kasp_policy_defaults(dnssec_kasp_policy_t *policy);
int dnssec_kasp_policy_save(dnssec_kasp_t *kasp, const dnssec_kasp_policy_t *policy);
int dnssec_kasp_policy_remove(dnssec_kasp_t *kasp, const char *name);
int dnssec_kasp_policy_list(dnssec_kasp_t *kasp, dnssec_list_t **list);

/* keystore.h */
struct dnssec_keystore {};
int dnssec_keystore_close(struct dnssec_keystore *store);
int dnssec_keystore_deinit(struct dnssec_keystore *store);
int dnssec_keystore_list_keys(struct dnssec_keystore *store, dnssec_list_t **list);
int dnssec_keystore_generate_key(struct dnssec_keystore *store, dnssec_key_algorithm_t algorithm, unsigned bits, char **id_ptr);
int dnssec_keystore_import(struct dnssec_keystore *store, const dnssec_binary_t *pem, char **id_ptr);
int dnssec_keystore_remove_key(struct dnssec_keystore *store, const char *id);
int dnssec_key_import_keystore(dnssec_key_t *key, struct dnssec_keystore *keystore, const char *id);

/* kasp.h - keystore */
typedef struct {
	const char *name;
	const char *backend;
	const char *config;
} dnssec_kasp_keystore_t;
int dnssec_kasp_keystore_load(dnssec_kasp_t *kasp, const char *name, dnssec_kasp_keystore_t **keystore);
int dnssec_kasp_keystore_save(dnssec_kasp_t *kasp, const dnssec_kasp_keystore_t *keystore);
int dnssec_kasp_keystore_exists(dnssec_kasp_t *kasp, const char *name);
int dnssec_kasp_keystore_init(dnssec_kasp_t *kasp, const char *backend, const char *config, struct dnssec_keystore **store);
int dnssec_kasp_keystore_open(dnssec_kasp_t *kasp, const char *backend, const char *config, struct dnssec_keystore **store);
void dnssec_kasp_keystore_free(dnssec_kasp_keystore_t *keystore);
]]

-- Crypto library initialiser/deinitialiser
lib.dnssec_crypto_init()
local crypto_init = ffi.gc(ffi.new('dnssec_binary_t'), function ()
	lib.dnssec_crypto_cleanup()
end)

-- Helper for error string
local function strerr(e)
	return ffi.string(lib.dnssec_strerror(e))
end

-- Helper to allow safe retrieval of wrapped key
local function getdata(v)
	assert(v and v.d[0] ~= nil)
	return v.d[0]
end

-- Helper to box string or byte array to datum struct
local tmp_binary = ffi.new('dnssec_binary_t')
local function boxdatum(data, len)
	if type(data) == 'string' or type(data) == 'cdata' then
		tmp_binary.data = ffi.cast('uint8_t *', data)
		tmp_binary.size = len or #data
		data = tmp_binary
	end
	return data
end

-- Get/set value from datum-like property
local function getsetdatum(key, get, set, data, len)
	if not data then
		if not get then return nil end
		local ret = get(key, tmp_binary)
		if ret ~= 0 then return nil, strerr(ret) end
		return ffi.string(tmp_binary.data, tmp_binary.size)
	end
	local ret = set(key, boxdatum(data, len))
	if ret ~= 0 then return nil, strerr(ret) end
	return true
end
local function getsetattr(key, get, set, val)
	if val then
		local ret = set(key, val)
		if ret ~= 0 then return nil, strerr(ret) end
	end
	return get(key)
end

-- RDATA digest size for given algorithm
local algorithms = {
	invalid = 0,
	dh = 1,
	dsa = 2,
	dsa_sha1 = 3,
	rsa_sha1 = 5,
	dsa_sha1_nsec3 = 6,
	rsa_sha1_nsec3 = 7,
	rsa_sha256 = 8,
	rsa_sha512 = 10,
	ecc_gost = 12,
	ecdsa_p256_sha256 = 13,
	ecdsa_p384_sha384 = 14,
	ed25519 = 15,
	ed448 = 16,
}

-- KASP key state
local keystate = {
	INVALID   = 0,
	PUBLISHED = 1,
	ACTIVE    = 2,
	RETIRED   = 3,
	REMOVED   = 4,
}

-- KASP keyset action
local keyaction = {
	ZSK_INIT    = 1,
	ZSK_PUBLISH = 2,
	ZSK_RESIGN  = 3,
	ZSK_RETIRE  = 4,
}

-- Declare module
local M = {
	algo = algorithms,
	action = keyaction,
	state = keystate,
	tostring = {
		algo = utils.itable(algorithms),
		action = utils.itable(keyaction),
		state = utils.itable(keystate),
	}
}

-- Metatype for DNSSEC key
local key_t = ffi.typeof('dnssec_key_t')
ffi.metatype(key_t, {
	__new = function (ct)
		local key = ffi.new('dnssec_key_t *[1]')
		local ret = lib.dnssec_key_new(key)
		if ret ~= 0 then return nil end
		return ffi.gc(key[0][0], lib.dnssec_key_free)
	end,
	__tostring = function(self)
		return tostring(self:tag())
	end,
	__index = {
		tag = function (self)
			return tonumber(lib.dnssec_key_get_keytag(self))
		end,
		name = function (self, name)
			local v, err = getsetattr(self, lib.dnssec_key_get_dname, lib.dnssec_key_set_dname, name)
			return v and v[0], err
		end,
		flags = function (self, flags)
			local v, err = getsetattr(self, lib.dnssec_key_get_flags, lib.dnssec_key_set_flags, flags)
			return v and tonumber(v), err
		end,
		ksk = function (self) return self:flags() == 257 end,
		zsk = function (self) return self:flags() == 256 end,
		protocol = function (self, proto)
			local v, err = getsetattr(self, lib.dnssec_key_get_protocol, lib.dnssec_key_set_protocol, proto)
			return v and tonumber(v), err
		end,
		algo = function (self, algo)
			local v, err = getsetattr(self, lib.dnssec_key_get_algorithm, lib.dnssec_key_set_algorithm, algo)
			return v and tonumber(v), err
		end,
		rdata = function (self, data, len)
			return getsetdatum(self, lib.dnssec_key_get_rdata, lib.dnssec_key_set_rdata, data, len)
		end,
		pubkey = function (self, data, len)
			return getsetdatum(self, lib.dnssec_key_get_pubkey, lib.dnssec_key_set_pubkey, data, len)
		end,
		privkey = function (self, pem, len)
			return getsetdatum(self, nil, lib.dnssec_key_load_pkcs8, pem, len)
		end,
		can_verify = function(self)
			return lib.dnssec_key_can_verify(self)
		end,
		can_sign = function(self)
			return lib.dnssec_key_can_sign(self)
		end,
	}
})
M.key = key_t

-- Metatype for DNSSEC signer
local function add_data(signer, data, len)
	local ret = lib.dnssec_sign_add(signer, boxdatum(data, len))
	if ret ~= 0 then return nil, strerr(ret) end
	return true
end
local tmp_hdr = ffi.new('struct { uint16_t t; uint16_t c; uint32_t l; }')
local tmp_signbuf = ffi.new('uint8_t [512]')
local signer_t = ffi.typeof('struct dnssec_signer')
ffi.metatype(signer_t, {
	__new = function (ct, key)
		-- Key is required for signer
		if not key then return end
		assert(ffi.istype(key_t, key), 'invalid key type')
		assert(key:can_sign(), 'key cannot be used for signing')
		local signer = ffi.new(ct)
		local ret = lib.dnssec_sign_new(signer.d, key)
		if ret ~= 0 then return nil, strerr(ret) end
		-- Cache frequently used key properties
		signer.algo = key:algo()
		signer.tag = key:tag()
		return signer
	end,
	__gc = function (self)
		lib.dnssec_sign_free(getdata(self))
	end,
	__index = {
		reset = function (self)
			local ret = lib.dnssec_sign_init(getdata(self))
			if ret ~= 0 then return nil, strerr(ret) end
			return true
		end,
		add = function (self, data, len)
			local signer = getdata(self)
			-- Serialise RRSet if passed as data
			if type(data) == 'cdata' and ffi.istype(data, dns.rrset) then
				local owner = data:owner()
				add_data(signer, owner.bytes, owner:len())
				tmp_hdr.t = utils.n16(data:type())
				tmp_hdr.c = utils.n16(data:class())
				tmp_hdr.l = utils.n32(data:ttl())
				assert(ffi.sizeof(tmp_hdr) == 8) -- Assert sane alignment
				-- Serialise records RDATA
				for _, rdata in ipairs(data) do
					add_data(signer, tmp_hdr, ffi.sizeof(tmp_hdr))
					add_data(signer, utils.rddata(rdata), utils.rdlen(rdata))
				end
			else
				return add_data(signer, data, len)
			end
		end,
		get = function (self)
			local ret = lib.dnssec_sign_write(getdata(self), tmp_binary)
			if ret ~= 0 then return nil, strerr(ret) end
			-- Must make a copy of binary and recycle
			ret = ffi.string(tmp_binary.data, tmp_binary.size)
			lib.dnssec_binary_free(tmp_binary)
			return ret
		end,
		verify = function (self, data, len)
			local signer = getdata(self)
			-- Verify (RR, RRSIG) if passed as data
			if type(data) == 'cdata' and ffi.istype(data, dns.rrset) then
				local rrsig = len
				assert(ffi.typeof(rrsig) == dns.rrset)
				assert(rrsig:type() == dns.type.RRSIG, 'second rr is not rrsig')
				self:reset()
				-- Add RRSIG header and signer
				local rrsig_data = rrsig:rdata(0)
				local w = utils.wire_reader(rrsig_data, #rrsig_data)
				self:add(w:bytes(18), 18) -- Add header
				local signer_len = utils.dnamelen(w:tell())
				self:add(w:bytes(signer_len), signer_len) -- Add signer
				local signature = w:bytes(w.maxlen - w.len)
				-- Add RRSet wire and verify against signature
				self:add(data)
				data, len = signature, #signature
			end
			-- Generic byte array verification
			local ret = lib.dnssec_sign_verify(signer, boxdatum(data, len))
			if ret ~= 0 then return nil, strerr(ret) end
			return true
		end,
		sign = function (self, rr, expire, incept, signer)
			self:reset()
			local owner = rr:owner()
			local rrsig = dns.rrset(owner, dns.type.RRSIG)
			local incept = incept or os.time()
			local labels = owner:labels()
			if owner:wildcard() then labels = labels - 1 end
			-- Need to manually fill the RRSIG header
			-- RFC4034 3.1.  RRSIG RDATA Wire Format
			local w = utils.wire_writer(tmp_signbuf, ffi.sizeof(tmp_signbuf))
			w:u16(rr:type())
			w:u8(self.algo)
			w:u8(labels)
			w:u32(rr:ttl())
			w:u32(incept + (expire or rr:ttl()))
			w:u32(incept)
			w:u16(self.tag)
			assert(w.len == 18)
			-- Either self-signed use given signer
			signer = signer or owner
			w:bytes(signer, signer:len())
			self:add(tmp_signbuf, w.len)
			-- Serialise RDATAs
			self:add(rr)
			-- Write down the RRSIG RDATA
			local digest = self:get()
			w:bytes(digest, #digest)
			rrsig:add(tmp_signbuf, rr:ttl(), w.len)
			return rrsig
		end,
	}
})
M.signer = signer_t

-- Helpers for keystore
local function init_keystore(kasp, name, backend, config)
	local ret = lib.dnssec_kasp_keystore_exists(kasp, name)
	if ret == 0 then return ret end
	local config = ffi.new('dnssec_kasp_keystore_t', {
		name or 'default', backend or 'pkcs8', config or 'keys'
	})
	local keystore = ffi.new('struct dnssec_keystore *[1]')
	ret = lib.dnssec_kasp_keystore_init(kasp, config.backend, config.config, keystore)
	if ret ~= 0 then return ret end
	return lib.dnssec_kasp_keystore_save(kasp, config)
end
local function list_free(t) lib.dnssec_list_free_full(t, nil, nil) end
local function keystore_iter(t, i)
	if i == nil then return end
	local id = ffi.cast('const char *', lib.dnssec_item_get(i))
	i = lib.dnssec_list_next(t, i)
	return i, ffi.string(id)
end
local function keystore_close(t)
	lib.dnssec_keystore_close(t)
	lib.dnssec_keystore_deinit(t)	
end

-- Metatype for KASP keystore
local policy_t = ffi.typeof('dnssec_kasp_policy_t')
local keystore_t = ffi.typeof('struct dnssec_keystore')
ffi.metatype(keystore_t, {
	__gc = keystore_close,
	__ipairs = function (self)
		local keys = ffi.new('dnssec_list_t *[1]')
		local ret = lib.dnssec_keystore_list_keys(self, keys)
		if ret ~= 0 then return end
		local list = ffi.gc(keys[0], list_free)
		return keystore_iter, list, lib.dnssec_list_head(list)
	end,
	__index = {
		generate = function (self, policy, ksk)
			assert(ffi.istype(policy, policy_t))
			local size = ksk and policy.ksk_size or policy.zsk_size
			local id = ffi.new('char *[1]')
			local ret = lib.dnssec_keystore_generate_key(self, policy.algorithm, size, id)
			if ret ~= 0 then return nil, strerr(ret) end
			local uuid = ffi.string(id[0])
			ffi.C.free(id[0])
			return self:get(policy, uuid, ksk)
		end,
		get = function (self, policy, id, ksk)
			assert(ffi.istype(policy, policy_t))
			local key = key_t()
			key:flags(ksk and 257 or 256)
			key:algo(policy.algorithm)
			local ret = lib.dnssec_key_import_keystore(key, self, id)
			if ret ~= 0 then return nil, strerr(ret) end
			return key, id
		end,
		del = function (self, id)
			local ret = lib.dnssec_keystore_remove_key(self, id)
			if ret ~= 0 then return nil, strerr(ret) end
			return true
		end,
	}
})

-- Metatype for KASP keyset, ljdns doesn't force concept of 'zones' in the same
-- way as the libdnssec used primarily for authoritative servers, but reuses the concept.
-- The keyset points to keystore and policy used for parameters for key generator, and
-- keeps track of timers and key expiration for automation.
local keyset_t = ffi.typeof('dnssec_kasp_zone_t')

local function keyset_iter(t, i)
	if i == nil then return end
	local e = ffi.cast('dnssec_kasp_key_t *', lib.dnssec_item_get(i))
	i = lib.dnssec_list_next(t, i)
	return i, {id=ffi.string(e.id), key=e.key[0], time=e.timing}
end

-- Check for presence of KSK/ZSK
local function keyset_check(keyset)
	local ksk, zsk
	for _, k in keyset:keys() do
		ksk = ksk or k.key:ksk()
		zsk = zsk or k.key:zsk()
	end
	return ksk, zsk
end

local function key_state(t, now)
	local removed = t.remove ~= 0 and t.remove <= now
	local retired = t.retire ~= 0 and t.retire <= now
	-- Check first if key is retired or removed
	if retired and removed then
		return keystate.REMOVED
	elseif retired and not removed then
		return keystate.RETIRED
	end
	-- Check if the key is still active
	local published = not removed and (t.publish == 0 or t.publish <= now)
	local activated = not retired and (t.active  == 0 or t.active  <= now)
	if published and activated then
		return keystate.ACTIVE
	elseif published and not activated then
		return keystate.PUBLISHED
	end
	return keystate.INVALID
end

local function key_newer(a, b)
	return b.time.created == 0 or b.time.created >= a.time.created
end

-- Find last key (in terms of creation time) matching given state
local function keyset_last(keyset, state, now, ksk)
	now = now or os.time()
	ksk = ksk or false
	local last
	for _, k in keyset:keys() do
		if ksk == k.key:ksk() and key_state(k.time, now) == state then
			if not last or key_newer(last, k) then 
				last = k
			end
		end
	end
	return last
end

-- Perform key rollover steps
local keyset_step = {
	-- Generate initial keys
	[keyaction.ZSK_INIT] = function (ks, now)
		now = now or os.time()
		local ksk, zsk = keyset_check(ks)
		if not ksk then
			assert(ks:generate(true, now, true))
		end
		if not zsk then
			assert(ks:generate(false, now, true))
		end
	end,
	[keyaction.ZSK_PUBLISH] = function (ks, now)
		now = now or os.time()
		local zsk, id, time = assert(ks:generate(false, now))
		-- Set as active in the future (maximum)
		time.publish = now 
		time.active = 0xffffffff
		assert(ks:save())
	end,
	[keyaction.ZSK_RESIGN] = function (ks, now)
		now = now or os.time()
		local active = keyset_last(ks, keystate.ACTIVE, now)
		local rolling = keyset_last(ks, keystate.PUBLISHED, now)
		-- Check if we have any key to roll over to/from
		if not active or not rolling then return end
		-- Update timing
		active.time.retire = now
		rolling.time.active = now
		assert(ks:save())
	end,
	[keyaction.ZSK_RETIRE] = function (ks, now)
		now = now or os.time()
		local retired = keyset_last(ks, keystate.RETIRED, now)
		-- Check if we have any key to roll over to/from
		if not retired then return end
		-- Update timing
		retired.time.remove = now
		assert(ks:save())
	end,	
}

local keyset_mt = {
	__ipairs = function (self)
		return self:keys()
	end,
	__index = {
		keys = function (self)
			local keys = lib.dnssec_kasp_zone_get_keys(self.data)
			if keys == nil then return end
			return keyset_iter, keys, lib.dnssec_list_head(keys)
		end,
		name = function (self)
			if self.data.name == nil then return end
			return ffi.string(self.data.name)
		end,
		policy = function (self, newpolicy)
			local oldpolicy
			if self.data.policy ~= nil then
				oldpolicy = ffi.string(self.data.policy)
			end
			if newpolicy and newpolicy ~= oldpolicy then
				local ret = lib.dnssec_kasp_zone_set_policy(self.data, newpolicy)
				if ret ~= 0 then return nil, strerr(ret) end
				assert(self:save())
			end
			return oldpolicy
		end,
		save = function (self)
			local ret = lib.dnssec_kasp_zone_save(self.kasp, self.data)
			if ret ~= 0 then return nil, strerr(ret) end
			return true
		end,
		add = function (self, key, id, now, init)
			local keys = lib.dnssec_kasp_zone_get_keys(self.data)
			if keys == nil then return end
			-- Build C-world kasp key
			local kd = ffi.cast('dnssec_kasp_key_t *', ffi.C.calloc(1, ffi.sizeof('dnssec_kasp_key_t')))
			assert(kd ~= nil, 'not enough memory')
			kd.id = ffi.C.strdup(id)
			assert(kd.id ~= nil, 'not enough memory')
			kd.key = ffi.gc(key, nil) -- Transfer ownership to list
			-- Update timing table
			now = now or os.time()
			kd.timing.created = now
			-- Add to keyset
			lib.dnssec_list_append(keys, kd)
			return key, id, kd.timing
		end,
		get = function (self, id)
			for _, k in self:keys() do
				if k.id == id then return k.key, k.id, k.time end
			end
		end,
		zsk = function (self, now)
			local zsk = keyset_last(self, keystate.ACTIVE, now)
			return zsk and zsk.key
		end,
		ksk = function (self, now)
			local ksk = keyset_last(self, keystate.ACTIVE, now, true)
			return ksk and ksk.key
		end,
		rolling = function (self, now)
			local key = keyset_last(self, keystate.PUBLISHED, now, true)
			return key and key.key
		end,
		generate = function (self, ksk, now, initial)
			-- Read policy and keystore for this keyset
			local policy, err = self.kasp:policy(self:policy())
			assert(policy, string.format('cannot read keyset policy: %s', err))
			local keystore, err = self.kasp:keystore(policy)
			assert(keystore, string.format('cannot read keyset keystore: %s', err))
			-- Generate a new key and add it to the keyset
			local key, id = keystore:generate(policy, ksk)
			if not key then return nil, id end
			local key, id, time = self:add(key, id, now)
			if initial then
				time.active = now
				time.publish = now
			end
			-- Save KASP state
			self:save()
			return key, id, time
		end,
		plan = function (self, now)
			-- Set initial state and check keys
			now = now or os.time()
			local has_ksk, has_zsk = keyset_check(self)
			if not has_ksk or not has_zsk then
				return now, keyaction.ZSK_INIT
			end
			local policy, err = self.kasp:policy(self:policy())
			assert(policy, string.format('cannot read keyset policy: %s', err))
			-- Check if we need to finish key rollover
			local k = keyset_last(self, keystate.RETIRED, now)
			if k then
				assert(now >= k.time.retire, 'key retired but retire time is in future')
				local when = (policy.propagation_delay + policy.zone_maximal_ttl) - (now - k.time.retire)
				return now + math.max(tonumber(when), 0), keyaction.ZSK_RETIRE
			end
			-- Check when we need start signing with new key
			local k = keyset_last(self, keystate.PUBLISHED, now)
			if k then
				assert(now >= k.time.publish, 'key published but publish time is in future')
				local when = (policy.propagation_delay + policy.dnskey_ttl) - (now - k.time.publish)
				return now + math.max(tonumber(when), 0), keyaction.ZSK_RESIGN
			end
			-- Check when we need to publish new key
			local k = keyset_last(self, keystate.ACTIVE, now)
			if k then
				assert(now >= k.time.publish, 'key published but publish time is in future')
				local when = (policy.zsk_lifetime) - (now - k.time.publish)
				return now + math.max(tonumber(when), 0), keyaction.ZSK_PUBLISH
			end
		end,
		action = function (self, action, now)
			if type(action) == 'string' then action = M.action[action] end
			assert(keyset_step[action], 'unknown keyset action: ' .. tostring(action))
			return keyset_step[action](self, now)
		end,
	}
}

-- Wrap keyset in metatable and reference KASP
local function keyset_create(keyset, kasp)
	if type(keyset) == 'string' then
		keyset = lib.dnssec_kasp_zone_new(keyset)
		keyset = ffi.gc(keyset[0], lib.dnssec_kasp_zone_free)
	end
	if keyset == nil then return end
	-- Wrap keyset in metatable
	keyset = setmetatable({data=keyset, kasp=kasp}, keyset_mt)
	-- Import all active keys
	local policy = keyset:policy()
	if policy then
		local now = os.time()
		local keystore = assert(kasp:keystore(policy))
		for _, k in keyset:keys() do
			local state = key_state(k.time, now)
			if state == keystate.ACTIVE then
				lib.dnssec_key_import_keystore(k.key, keystore, k.id)
			end
		end
	end
	return keyset
end
M.keyset = keyset_create

-- Metatype for KASP
local function kasp_close(kasp)
	lib.dnssec_kasp_close(kasp)
	lib.dnssec_kasp_deinit(kasp)
end
local kasp_t = ffi.typeof('dnssec_kasp_t')
ffi.metatype(kasp_t, {
	__new = function (ct, path)
		local kasp = ffi.new('dnssec_kasp_t *[1]')
		local ret = lib.dnssec_kasp_init_dir(kasp)
		if ret ~= 0 then return nil, strerr(ret) end
		-- Open/init KASP directory
		utils.mkdir(path, '0700')
		ret = lib.dnssec_kasp_open(kasp[0], path)
		if ret ~= 0 then return nil, strerr(ret) end
		-- Make sure default keystore is available
		kasp = ffi.gc(kasp[0][0], kasp_close)
		init_keystore(kasp)
		return kasp
	end,
	__index = {
		policy = function (self, id, desc)
			local ret = lib.dnssec_kasp_policy_exists(self, id)
			local exists = (ret == 0)
			-- Update policy
			if desc ~= nil then
				if exists and desc == false then
					ret = lib.dnssec_kasp_policy_remove(self, id)
					if ret ~= 0 then return nil, strerr(ret) end
					return true
				elseif not exists then
					local policy = ffi.new(policy_t)
					-- Set defaults and fill remaining fields
					lib.dnssec_kasp_policy_defaults(policy)
					policy.name, policy.keystore = id, 'default'
					for k,v in pairs(desc) do
						if k == 'algorithm' then v = algorithms[v] or 0 end
						policy[k] = v
					end
					ret = lib.dnssec_kasp_policy_validate(policy)
					if ret ~= 0 then return nil, strerr(ret) end
					ret = lib.dnssec_kasp_policy_save(self, policy)
					if ret ~= 0 then return nil, strerr(ret) end
				end
			end
			-- Load the policy
			local policy = ffi.new('dnssec_kasp_policy_t *[1]')
			ret = lib.dnssec_kasp_policy_load(self, id, policy)
			if ret ~= 0 then return nil, strerr(ret) end
			return ffi.gc(policy[0][0], lib.dnssec_kasp_policy_free)
		end,
		keystore = function (self, id, t)
			if ffi.istype(policy_t, id) then id = id.keystore end
			-- Set keystore configuration
			if type(t) == 'table' then
				local ret = init_keystore(self, id, t.backend, t.config)
				if ret ~= 0 then return nil, strerr(ret) end
			end
			-- Get keystore configuration
			local config = ffi.new('dnssec_kasp_keystore_t *[1]')
			local ret = lib.dnssec_kasp_keystore_load(self, id, config)
			if ret ~= 0 then return nil, strerr(ret) end
			-- Open keystore
			local store = ffi.new('struct dnssec_keystore *[1]')
			ret = lib.dnssec_kasp_keystore_open(self, config[0].backend, config[0].config, store)
			lib.dnssec_kasp_keystore_free(config[0])
			if ret ~= 0 then return nil, strerr(ret) end
			return ffi.gc(store[0][0], keystore_close)
		end,
		keyset = function (self, name, t)
			-- Retrieve keyset from KASP
			local ks = ffi.new('dnssec_kasp_zone_t *[1]')
			local ret = lib.dnssec_kasp_zone_load(self, name, ks)
			-- Create if not exists and configuration passed
			if ret ~= 0 and type(t) == 'table' then
				ks[0] = lib.dnssec_kasp_zone_new(name)
				if ks[0] ~= nil then ret = 0 end
			end
			if ret ~= 0 then return nil, strerr(ret) end
			ks = keyset_create(ffi.gc(ks[0][0], lib.dnssec_kasp_zone_free), self)
			-- Set/update keystore configuration in KASP
			if type(t) == 'table' then
				if t.policy then ks:policy(t.policy) end
			end
			return ks
		end,
	}
})
M.kasp = kasp_t

-- Whitelist supported DNS types
local known_types = {}
for _, t in pairs(dns.type) do
	if t < 127 then table.insert(known_types, t) end
end
-- NSEC "black lies" denialer
local tmp_bitmap = ffi.gc(lib.dnssec_nsec_bitmap_new(), lib.dnssec_nsec_bitmap_free)
M.denial = function (name, rrtype, ttl, nxdomain)
	local nsec = dns.rrset(name, dns.type.NSEC)
	local next_name = dns.dname('\1\0' .. name:towire())
	local next_len = next_name:len()
	-- Construct NSEC bitmap with all basic types byt requested
	lib.dnssec_nsec_bitmap_clear(tmp_bitmap)
	-- NXDOMAIN can contain only NSEC and its RRSIG
	if nxdomain then
		lib.dnssec_nsec_bitmap_add(tmp_bitmap, dns.type.NSEC)
		lib.dnssec_nsec_bitmap_add(tmp_bitmap, dns.type.RRSIG)
	else -- All supported types up to meta types
		for _, i in ipairs(known_types) do
			if i ~= rrtype and i <= 127 then
				lib.dnssec_nsec_bitmap_add(tmp_bitmap, i)
			end
		end
	end
	-- Create NSEC RDATA
	local bit_size = lib.dnssec_nsec_bitmap_size(tmp_bitmap)
	local rdata = utils.wire_writer(tmp_signbuf, next_len + bit_size)
	assert(next_len + bit_size < ffi.sizeof(tmp_signbuf))
	rdata:bytes(next_name.bytes, next_len)
	lib.dnssec_nsec_bitmap_write(tmp_bitmap, rdata:tell())
	rdata:seek(bit_size)
	-- Finalize RRSET
	nsec:add(rdata.p, ttl or 0, rdata.len)
	return nsec
end

-- Extend DNS record dissectors
dns.rdata.rrsig_signature = function(rdata)
	local w = utils.wire_reader(rdata, utils.rdlen(rdata))
	w:seek(18) -- Skip header
	local signer_len = utils.dnamelen(w:tell())
	w:seek(signer_len) -- Skip signer name
	return w:bytes(w.maxlen - w.len)
end
-- Extened DNS RDATA constructors
dns.rdata.dnskey = function(flags, proto, algo, pubkey, pubkey_len)
	pubkey_len = pubkey_len or #pubkey
	local rdata = ffi.new('char [?]', ffi.sizeof('uint32_t') + pubkey_len)
	local w = utils.wire_writer(rdata, ffi.sizeof(rdata))
	w:u16(flags)
	w:u8(proto)
	w:u8(algo)
	w:bytes(pubkey, pubkey_len)
	assert(w.len == ffi.sizeof(rdata))
	return rdata
end

return M