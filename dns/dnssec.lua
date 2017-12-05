local ffi = require('ffi')
local utils = require('dns.utils')
local dns = require('dns')
local lib = utils.clib('dnssec', {2, 3, 4, 5})
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
]]

-- Crypto library initialiser/deinitialiser
lib.dnssec_crypto_init()
local crypto_init = ffi.gc(ffi.new('dnssec_binary_t'), function () -- luacheck: ignore
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
	__new = function ()
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
					add_data(signer, dns.rdata.data(rdata), dns.rdata.len(rdata))
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
			local labels = owner:labels()
			incept = incept or os.time()
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