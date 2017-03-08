-- A contemporary LuaJIT DNS library using FFI.

local ffi = require('ffi')
local bit = require('bit')
local math = require('math')
local utils = require('dns.utils')
local n16, n32 = utils.n16, utils.n32
local knot = utils.knot

ffi.cdef[[
/*
 * Data structures
 */
typedef struct {
	bool	wrap;
	bool	show_class;
	bool	show_ttl;
	bool	verbose;
	bool	empty_ttl;
	bool	human_ttl;
	bool	human_tmstamp;
	bool	generic;
	void (*ascii_to_idn)(char **name);
} knot_dump_style_t;
typedef int knot_section_t; /* Do not touch */
typedef void knot_rrinfo_t; /* Do not touch */
typedef struct knot_dname { uint8_t bytes[?]; } knot_dname_t;
typedef struct knot_rrset {
	knot_dname_t *raw_owner; /* This is private because GC-unaware */
	uint16_t raw_type;
	uint16_t raw_class;
	uint32_t __pad__;        /* Padding because libknot uses nested structure */
	uint16_t rdcount;
	knot_rdata_t *raw_data;
	void *additional;
} knot_rrset_t;
typedef struct {
	struct knot_pkt *pkt;
	uint16_t pos;
	uint16_t count;
} knot_pktsection_t;
typedef struct {
	uint8_t *wire;
	size_t size;
	size_t max_size;
	size_t parsed;
	uint16_t reserved;
	uint16_t qname_size;
	uint16_t rrset_count;
	uint16_t flags;
	knot_rrset_t *opt;
	knot_rrset_t *tsig;
	struct {
		uint8_t *pos;
		size_t len;
	} _tsig_wire;
	knot_section_t cur_section;
	knot_pktsection_t _sections[3];
	size_t _rrset_allocd;
	knot_rrinfo_t *_rr_info;
	knot_rrset_t *_rr;
	uint8_t _stub[]; /* Do not touch */
} knot_pkt_t;
typedef struct {
	size_t size;
	uint8_t *data;
} dnssec_binary_t;
typedef struct {
	int algorithm;
	knot_dname_t *name;
	dnssec_binary_t secret;
} knot_tsig_key_t;
typedef struct {
	knot_tsig_key_t key;
	size_t digest_len;
	uint64_t last_signed;
	uint8_t digest[64]; /* Max size of the HMAC-SHA512 */
} tsig_t;
/* descriptors */
const char *knot_strerror(int code);
int knot_rrtype_to_string(uint16_t rrtype, char *out, size_t out_len);
/* domain names */
knot_dname_t *knot_dname_from_str(uint8_t *dst, const char *name, size_t maxlen);
char *knot_dname_to_str(char *dst, const uint8_t *name, size_t maxlen);
int knot_dname_to_lower(uint8_t *name);
int knot_dname_labels(const uint8_t *name, const uint8_t *pkt);
bool knot_dname_in(const uint8_t *domain, const uint8_t *sub);
knot_dname_t *knot_dname_copy(const void *name, void /* mm_ctx_t */ *mm);
int knot_dname_unpack(uint8_t *dst, const uint8_t *src, size_t maxlen, const uint8_t *pkt);
/* resource records */
extern const knot_dump_style_t KNOT_DUMP_STYLE_DEFAULT;
uint32_t knot_rdata_ttl(const knot_rdata_t *rr);
void knot_rdata_set_ttl(knot_rdata_t *rr, uint32_t ttl);
int knot_rrset_txt_dump(const knot_rrset_t *rrset, char **dst, size_t *maxlen, const knot_dump_style_t *style);
int knot_rrset_txt_dump_data(const knot_rrset_t *rrset, size_t pos, char *dst, size_t maxlen, const knot_dump_style_t *style);
int knot_rrset_add_rdata(knot_rrset_t *rrset, const uint8_t *rdata, const uint16_t size, const uint32_t ttl, void *mm);
/* opt rr */
uint8_t knot_edns_get_version(const knot_rrset_t *opt_rr);
void knot_edns_set_version(knot_rrset_t *opt_rr, uint8_t version);
int knot_edns_add_option(knot_rrset_t *opt_rr, uint16_t code, uint16_t length, const uint8_t *data, void *mm);
bool knot_edns_has_option(const knot_rrset_t *opt_rr, uint16_t code);
uint8_t *knot_edns_get_option(const knot_rrset_t *opt_rr, uint16_t code);
uint16_t knot_edns_opt_get_length(const uint8_t *opt);
size_t knot_edns_wire_size(knot_rrset_t *opt_rr);
void knot_edns_set_ext_rcode(knot_rrset_t *opt_rr, uint8_t ext_rcode);
uint8_t knot_edns_get_ext_rcode(const knot_rrset_t *opt_rr);
/* packet */
knot_dname_t *knot_pkt_qname(const knot_pkt_t *pkt);
uint16_t knot_pkt_qtype(const knot_pkt_t *pkt);
uint16_t knot_pkt_qclass(const knot_pkt_t *pkt);
int knot_pkt_begin(knot_pkt_t *pkt, int section_id);
const knot_rrset_t *knot_pkt_rr(const knot_pktsection_t *section, uint16_t i);
const knot_pktsection_t *knot_pkt_section(const knot_pkt_t *pkt, knot_section_t section_id);
knot_pkt_t *knot_pkt_new(void *wire, uint16_t len, /* mm_ctx_t */ void *mm);
int knot_pkt_put(knot_pkt_t *pkt, uint16_t compr_hint, const knot_rrset_t *rr, uint16_t flags);
int knot_pkt_put_question(knot_pkt_t *pkt, const knot_dname_t *qname,
                          uint16_t qclass, uint16_t qtype);
int knot_pkt_parse(knot_pkt_t *pkt, unsigned flags);
int knot_pkt_parse_section(knot_pkt_t *pkt, unsigned flags);
int knot_pkt_parse_question(knot_pkt_t *pkt);
void knot_pkt_clear(knot_pkt_t *pkt);
void knot_pkt_free(knot_pkt_t **pkt);
/* tsig */
int knot_tsig_key_init_str(knot_tsig_key_t *key, const char *params);
int knot_tsig_key_init_file(knot_tsig_key_t *key, const char *filename);
int knot_tsig_key_copy(knot_tsig_key_t *dst, const knot_tsig_key_t *src);
void knot_tsig_key_deinit(knot_tsig_key_t *key);
int knot_tsig_sign(uint8_t *msg, size_t *msg_len, size_t msg_max_len,
                   const uint8_t *request_mac, size_t request_mac_len,
                   uint8_t *digest, size_t *digest_len,
                   const knot_tsig_key_t *key, uint16_t tsig_rcode,
                   uint64_t request_time_signed);
int knot_tsig_client_check(const knot_rrset_t *tsig_rr,
                           const uint8_t *wire, size_t size,
                           const uint8_t *request_mac, size_t request_mac_len,
                           const knot_tsig_key_t *key,
                           uint64_t prev_time_signed);
const uint8_t *knot_tsig_rdata_mac(const knot_rrset_t *tsig);
size_t knot_tsig_rdata_mac_length(const knot_rrset_t *tsig);
uint64_t knot_tsig_rdata_time_signed(const knot_rrset_t *tsig);
]]

-- Basic types
local void_p = ffi.typeof('void *')
local u8_p = ffi.typeof('uint8_t *')
local u16_p = ffi.typeof('uint16_t *')
local u32_p = ffi.typeof('uint32_t *')

-- Constants
local const_class = {
	IN         =   1,
	CH         =   3,
	NONE       = 254,
	ANY        = 255,
}
local const_type = {
	A          =   1,
	NS         =   2,
	CNAME      =   5,
	SOA        =   6,
	PTR        =  12,
	HINFO      =  13,
	MINFO      =  14,
	MX         =  15,
	TXT        =  16,
	RP         =  17,
	AFSDB      =  18,
	RT         =  21,
	SIG        =  24,
	KEY        =  25,
	AAAA       =  28,
	LOC        =  29,
	SRV        =  33,
	NAPTR      =  35,
	KX         =  36,
	CERT       =  37,
	DNAME      =  39,
	OPT        =  41,
	APL        =  42,
	DS         =  43,
	SSHFP      =  44,
	IPSECKEY   =  45,
	RRSIG      =  46,
	NSEC       =  47,
	DNSKEY     =  48,
	DHCID      =  49,
	NSEC3      =  50,
	NSEC3PARAM =  51,
	TLSA       =  52,
	CDS        =  59,
	CDNSKEY    =  60,
	SPF        =  99,
	NID        = 104,
	L32        = 105,
	L64        = 106,
	LP         = 107,
	EUI48      = 108,
	EUI64      = 109,
	TKEY       = 249,
	TSIG       = 250,
	IXFR       = 251,
	AXFR       = 252,
	ANY        = 255,
}
local const_section = {
	ANSWER     = 0,
	AUTHORITY  = 1,
	ADDITIONAL = 2,
}
local const_opcode = {
	QUERY      = 0,
	IQUERY     = 1,
	STATUS     = 2,
	NOTIFY     = 4,
	UPDATE     = 5,
}
local const_rcode = {
	NOERROR    =  0,
	FORMERR    =  1,
	SERVFAIL   =  2,
	NXDOMAIN   =  3,
	NOTIMPL    =  4,
	REFUSED    =  5,
	YXDOMAIN   =  6,
	YXRRSET    =  7,
	NXRRSET    =  8,
	NOTAUTH    =  9,
	NOTZONE    = 10,
	BADVERS    = 16,
	BADCOOKIE  = 23,
}
local const_rcode_tsig = {
	BADSIG     = 16,
	BADKEY     = 17,
	BADTIME    = 18,
	BADTRUNC   = 22,
}
local const_opt = {
	NSID        = 3,
	SUBNET      = 8,
	EXPIRE      = 9,
	COOKIE      = 10,
}

-- Constant tables
local const_class_str = utils.itable(const_class)
local const_type_str = utils.itable(const_type)
setmetatable(const_type_str, {
	__index = function (t, k)
		local v = rawget(t, k)
		if v then return v end
		local str = ffi.new('char [?]', 16)
		knot.knot_rrtype_to_string(k, str, 16)
		return (ffi.string(str))
	end
})
local const_rcode_str = utils.itable(const_rcode)
local const_opcode_str = utils.itable(const_opcode)
local const_section_str = utils.itable(const_section)
local const_section_str_lower = {
	[0] = 'Answer', [1] = 'Authority', [2] = 'Additional',
}
local const_rcode_tsig_str = utils.itable(const_rcode_tsig)
local const_opt_str = utils.itable(const_opt)

-- TSIG error to TSIG RCODE mapping
-- @note this expects libknot error codes don't change
local const_errcode_tsig = {
	[0] = true,
	[-947] = const_rcode_tsig.BADSIG,
	[-946] = const_rcode_tsig.BADKEY,
	[-945] = const_rcode_tsig.BADTIME,
	[-944] = const_rcode_tsig.BADTRUNC,
}

-- Check if type is meta type
setmetatable(const_type, {__index = {
	ismeta = function (t)
		return t > 127 and t <= const_type.ANY or t == const_type.OPT
	end
}})

local function strerr(r)
	return ffi.string(knot.knot_strerror(r))
end

-- Metatype for domain name
local dname_buf = ffi.new('char [?]', 256)
local knot_dname_t = ffi.typeof('knot_dname_t')
ffi.metatype( knot_dname_t, {
	__new = function (ct, name, len)
		assert(name ~= nil)
		len = len or #name
		local dname = ffi.new(ct, len + 1)
		-- Check input wire format, malformed names must not be passed through this point
		if knot.knot_dname_unpack(dname.bytes, name, len + 1, nil) <= 0 then
			dname = nil
		end
		return dname
	end,
	__tostring = function(dname)
		return dname:tostring()
	end,
	__len = function(dname)
		return dname:len()
	end,
	__eq = function(a, b)
		return (a:equals(b))
	end,
	__lt = function (a,b)
		return a:compare(b) < 0
	end,
	__index = {
		copy = function(dname)
			assert(ffi.istype(knot_dname_t, dname))
			assert(dname.bytes ~= nil)
			return knot_dname_t(dname.bytes, #dname)
		end,
		equals = function(a, b, len)
			if b == nil then return false end
			-- RHS has a specified length, use it
			if len then
				return a:len() == len and (ffi.C.memcmp(a.bytes, b, len) == 0)
			end
			-- RHS may be Lua string, but then it need to be converted
			-- for dname wire check, this is slower than comparing casted values
			if type(b) == 'string' then b = knot_dname_t(b) end
			local l1, l2 = a:len(), b:len()
			return l1 == l2 and (ffi.C.memcmp(a.bytes, b.bytes, l1) == 0)
		end,
		compare = function(a, b)
			assert(ffi.istype(knot_dname_t, a))
			return utils.dnamecmp(a, b)
		end,
		parse = function(name)
			local dname = knot.knot_dname_from_str(dname_buf, name, 255)
			if dname == nil then return nil end
			return knot_dname_t(dname[0].bytes, dname[0]:len())
		end,
		lower = function(dname) -- Copy to make sure it's safely mutable
			local copy = dname:copy()
			knot.knot_dname_to_lower(copy.bytes)
			return copy
		end,
		len = function(dname)
			assert(ffi.istype(knot_dname_t, dname))
			assert(dname.bytes ~= nil)
			return (utils.dnamelen(dname.bytes))
		end,
		labels = function(dname)
			assert(ffi.istype(knot_dname_t, dname))
			assert(dname.bytes ~= nil)
			return (knot.knot_dname_labels(dname.bytes, nil))
		end,
		within = function(dname, parent)
			assert(ffi.istype(knot_dname_t, dname))
			assert(parent ~= nil)
			if ffi.istype(knot_dname_t, parent) then parent = parent.bytes end
			return (knot.knot_dname_in(ffi.cast(u8_p, parent), dname.bytes) == true)
		end,
		wildcard = function(dname)
			assert(ffi.istype(knot_dname_t, dname))
			assert(dname.bytes ~= nil)
			return dname.bytes[0] == 1 and dname.bytes[1] == 42 -- '\1*'
		end,
		parentof = function(dname, child)
			assert(ffi.istype(knot_dname_t, child))
			assert(child ~= nil)
			return child:within(dname)
		end,
		towire = function(dname, len)
			assert(ffi.istype(knot_dname_t, dname))
			assert(dname.bytes ~= nil)
			return (ffi.string(dname.bytes, len or dname:len()))
		end,
		tostring = function(dname)
			assert(ffi.istype(knot_dname_t, dname))
			assert(dname.bytes ~= nil)
			return (ffi.string(knot.knot_dname_to_str(dname_buf, dname.bytes, 255)))
		end,
		split = function(dname)
			assert(ffi.istype(knot_dname_t, dname))
			assert(dname.bytes ~= nil)
			local t, p, i = {}, dname.bytes, 0
			while p[i] ~= 0 do
				table.insert(t, ffi.string(p + i + 1, p[i]))
				i = i + p[i] + 1
			end
			return t
		end,
	},
})

-- RDATA parser
local rrparser
local function rd_parse (rdata_str)
	if not rrparser then
		rrparser = require('dns.rrparser').new()
	end
	rrparser:reset()
	if rrparser:parse(string.format('. 0 IN %s\n', rdata_str)) then
		return ffi.string(rrparser.r_data, rrparser.r_data_length)
	else return nil end
end

-- Metatype for RDATA
local rdata = {
	parse = rd_parse,
	-- Selected types / pure parsers
	a = function (rdata_str) return rd_parse('A '..rdata_str) end,
	aaaa = function (rdata_str) return rd_parse('AAAA '..rdata_str) end,
	soa = function (rdata_str) return rd_parse('SOA '..rdata_str) end,
	ns = function (rdata_str) return rd_parse('NS '..rdata_str) end,
	txt = function (rdata_str) return rd_parse('TXT '..rdata_str) end,
	srv = function (priority, port, weight, target)
		local wire = ffi.new('char [?]', 3 * ffi.sizeof('uint16_t') + target:len())
		local p = ffi.cast(u16_p, wire)
		p[0] = n16(priority)
		p[1] = n16(port)
		p[2] = n16(weight)
		ffi.copy(p + 3, target.bytes, target:len())
		return wire
	end,
	mx = function (priority, target)
		if type(priority) == 'string' then
			return rd_parse('MX '..priority)
		end
		local wire = ffi.new('char [?]', ffi.sizeof('uint16_t') + target:len())
		local p = ffi.cast(u16_p, wire)
		p[0] = n16(priority)
		ffi.copy(p + 1, target.bytes, target:len())
		return wire
	end,
	-- RDATA disection routines (extensible)
	soa_primary_ns = function(rdata)
		rdata = ffi.cast(u8_p, rdata)
		return knot_dname_t(rdata, utils.dnamelen(rdata))
	end,
	soa_mailbox = function(rdata)
		rdata = ffi.cast(u8_p, rdata)
		rdata = rdata + utils.dnamelen(rdata) -- Primary NS
		return knot_dname_t(rdata, utils.dnamelen(rdata))
	end,
	soa_serial = function(rdata)
		rdata = ffi.cast(u8_p, rdata)
		rdata = rdata + utils.dnamelen(rdata) -- Primary NS
		rdata = rdata + utils.dnamelen(rdata) -- Mailbox
		return n32(ffi.cast(u32_p, rdata)[0])
	end,
	soa_minttl = function(rdata)
		rdata = ffi.cast(u8_p, rdata)
		rdata = rdata + utils.dnamelen(rdata) -- Primary NS
		rdata = rdata + utils.dnamelen(rdata) -- Mailbox
		rdata = rdata + 4 * ffi.sizeof('uint32_t')
		return n32(ffi.cast(u32_p, rdata)[0])
	end,
}

-- Metatype for RDATA
local knot_rdata_t = ffi.typeof('knot_rdata_t')
ffi.metatype( knot_rdata_t, {
	__tostring = function (self)
		return ffi.string(self:data(), self:len())
	end,
	__len = function (self) return self:len() end,
	__index = {
		len = knot.knot_rdata_rdlen,
		data = knot.knot_rdata_data,
	}
})

-- Metatype for RR set
local rrset_buflen = (64 + 1) * 1024
local rrset_buf = ffi.new('char [?]', rrset_buflen)
local knot_rrset_t = ffi.typeof('knot_rrset_t')
ffi.metatype( knot_rrset_t, {
	__gc = function (rr)
		if rr.raw_owner ~= nil then ffi.C.free(rr.raw_owner) end
		if rr.rdcount > 0 then ffi.C.free(rr.raw_data) end
	end,
	__new = function (ct, owner, rrtype, rrclass, ttl)
		local rr = ffi.new(ct)
		rr.raw_owner = owner and knot.knot_dname_copy(owner, nil)
		rr.raw_type = rrtype or 0
		rr.raw_class = rrclass or const_class.IN
		return rr
	end,
	__lt = function (a, b) return a:lt(a, b) end,
	__tostring = function(rr) return rr:tostring() end,
	__ipairs = function (self) return utils.rdataiter, self, {-1,self.raw_data.bytes} end,
	__index = {
		lt = function (a, b)
			assert(ffi.istype(knot_rrset_t, a))
			assert(ffi.istype(knot_rrset_t, b))
			local ret = utils.dnamecmp(a:owner(), b:owner())
			if ret == 0 then ret = a:type() - b:type() end
			return ret < 0
		end,
		equals = function (a, b)
			assert(ffi.istype(knot_rrset_t, a))
			assert(ffi.istype(knot_rrset_t, b))
			return a:type() == b:type() and a:owner():equals(b:owner())
		end,
		owner = function(rr) return rr.raw_owner[0] end,
		type = function(rr) return rr.raw_type end,
		class = function(rr) return rr.raw_class end,
		ttl = function(rr, ttl)
			assert(ffi.istype(knot_rrset_t, rr))
			if rr.rdcount > 0 then
				if ttl ~= nil then knot.knot_rdata_set_ttl(rr.raw_data, ttl) end
				return tonumber(knot.knot_rdata_ttl(rr.raw_data))
			else return 0 end
		end,
		rdata = function(rr, i)
			assert(ffi.istype(knot_rrset_t, rr))
			local rdata = utils.rdsetget(rr, i)
			return ffi.string(knot.knot_rdata_data(rdata), knot.knot_rdata_rdlen(rdata))
		end,
		count = function (rr)
			return tonumber(rr.rdcount)
		end,
		empty = function (rr)
			return rr.rdcount == 0
		end,
		get = function(rr, i)
			assert(ffi.istype(knot_rrset_t, rr))
			return {owner = rr:owner(),
			        ttl = rr:ttl(),
			        class = tonumber(rr:class()),
			        type = tonumber(rr:type()),
			        rdata = rr:rdata(i)}
		end,
		init = function (rr, owner, rrtype, rrclass)
			assert(ffi.istype(knot_rrset_t, rr))
			rr.raw_type = rrtype or 0
			rr.raw_class = rrclass or const_class.IN
			-- @note RR set structure is managed by LuaJIT allocator, the owner and contents is
			--       managed on the C side as GC is unaware of assignments in struct fields
			if rr.raw_owner ~= nil then
				ffi.C.free(rr.raw_owner)
				rr.raw_owner = nil
			end
			if owner then
				rr.raw_owner = knot.knot_dname_copy(owner, nil)
			end
			rr.rdcount = 0
			rr.raw_data = nil
			return rr
		end,
		add = function(rr, rdata, ttl, rdlen)
			assert(ffi.istype(knot_rrset_t, rr))
			ttl = ttl or rr:ttl()
			rdlen = rdlen or #rdata
			return (knot.knot_rrset_add_rdata(rr, rdata, rdlen, ttl, nil) == 0 and rr)
		end,
		copy = function (rr, dst)
			assert(ffi.istype(knot_rrset_t, rr))
			if dst then
				assert(ffi.istype(knot_rrset_t, rr))
				dst:init(rr:owner(), rr:type(), rr:class())
			else
				dst = knot_rrset_t(rr:owner(), rr:type(), rr:class())
			end
			if rr.rdcount > 0 then
				dst.rdcount = rr.rdcount
				local rdlen = utils.rdsetlen(rr)
				dst.raw_data = ffi.C.calloc(1, rdlen)
				ffi.copy(dst.raw_data, rr.raw_data, rdlen)
			end
			return dst
		end,
		merge = function (rr, next)
			assert(ffi.istype(knot_rrset_t, rr))
			assert(ffi.istype(knot_rrset_t, next))
			for _, rdata in ipairs(next) do
				local rdlen = knot.knot_rdata_rdlen(rdata)
				assert(rr:add(knot.knot_rdata_data(rdata), rr:ttl(), rdlen))
			end
		end,
		clear = function (rr)
			assert(ffi.istype(knot_rrset_t, rr))
			if rr.rdcount > 0 then
				ffi.C.free(rr.raw_data)
				rr.rdcount = 0
				rr.raw_data = nil
			end
		end,
		tostring = function(rr, i)
			assert(ffi.istype(knot_rrset_t, rr))
			if rr:count() > 0 then
				local ret
				if i then
					ret = knot.knot_rrset_txt_dump_data(rr, i, rrset_buf, rrset_buflen, knot.KNOT_DUMP_STYLE_DEFAULT)
				else
					if rr.raw_owner == nil then return end -- Uninitialised RR set
					local buf = ffi.new('char *[1]', rrset_buf)
					local len = ffi.new('size_t [1]', rrset_buflen)
					ret = knot.knot_rrset_txt_dump(rr, buf, len, knot.KNOT_DUMP_STYLE_DEFAULT)
				end
				if ret < 0 then return nil, strerr(ret) end
				return ffi.string(rrset_buf)
			else
				return string.format('%s\t%s\t%s', rr:owner(), const_class_str[rr:class()], const_type_str[rr:type()])
			end
		end,
	}
})

-- Functions for OPT RR
local function edns_version(rr, val)
	if val ~= nil then knot.knot_edns_set_version(rr, val) end
	return (knot.knot_edns_get_version(rr))
end
local function edns_payload(rr, val)
	if val ~= nil then rr.raw_class = val end
	return rr:class()
end
local function edns_do(rr, val, raw)
	if rr == nil then return false end
	local ttl = rr:ttl()
	if val ~= nil then
		ttl = bit.bor(ttl, val and 0x8000 or 0x00)
		rr:ttl(ttl)
		return true
	else
		return bit.band(ttl, 0x8000) ~= 0
	end
end
local function edns_flags(rr)
	if rr == nil then return 0 end
	return rr:ttl()
end
local function edns_hasoption(rr, code)
	if rr == nil then return false end
	return (knot.knot_edns_has_option(rr, code))
end
local function edns_option(rr, code, val, len)
	if rr == nil then return false, 'nil rr' end
	if val ~= nil then
		len = len or #val
		knot.knot_edns_add_option(rr, code, len, ffi.cast('void *', val), nil)
		return edns_hasoption(rr, code)
	else
		local opt = knot.knot_edns_get_option(rr, code)
		if opt ~= nil then
			-- Skip option code and length and return only data
			len = knot.knot_edns_opt_get_length(opt)
			return (ffi.string(opt + 4, len))
		end
	end
end
local function edns_init(rr, version, payload)
	assert(rr)
	if version == nil then version = 0 end
	if payload == nil then payload = 4096 end
	-- Clear OPTs
	rr:clear()
	rr:add('', 0)
	-- Set payload/version
	edns_payload(rr, payload)
	edns_version(rr, version)
end
local function edns_t(version, payload)
	local rr = knot_rrset_t('\0', const_type.OPT, payload)
	edns_init(rr, version, payload)
	return rr
end

-- Metatype for packet section
local function pktsection_iter(t, i)
	i = i + 1
	if i >= t.count then return end
	return i, t[i][0]
end
ffi.metatype(ffi.typeof('knot_pktsection_t'), {
	__len = function (t) return t.count end,
	__index = function (t, k)
		assert(k < t.count)
		return (knot.knot_pkt_rr(t, k))
	end,
	__ipairs = function (t)
		return pktsection_iter, t, -1
	end
})

-- Metatype for packet
local knot_pkt_t = ffi.typeof('knot_pkt_t')
local function pkt_cnt(pkt, off, val)
	local ptr = ffi.cast(u16_p, pkt.wire + off)
	if val ~= nil then ptr[0] = n16(val) end
	return (n16(ptr[0]))
end
local function pkt_flags(pkt, idx, off, val)
	if val ~= nil then
		if val then pkt.wire[idx] = bit.bor(pkt.wire[idx], off)
		else pkt.wire[idx] = bit.band(pkt.wire[idx], bit.bnot(off)) end
		return true
	end
	return (bit.band(pkt.wire[idx], off) ~= 0)
end
local function section_tostring(pkt, sec_id, plain)
	local data = {}
	local tojson = (plain == 'json')
	local section = knot.knot_pkt_section(pkt, sec_id)
	if section.count > 0 then
		if not plain then
			table.insert(data, string.format(';; %s\n', const_section_str[sec_id]))
		end
		for j = 0, section.count - 1 do
			local rrset = knot.knot_pkt_rr(section, j)
			local rrtype = rrset:type()
			if rrtype ~= const_type.OPT and rrtype ~= const_type.TSIG then
				if tojson then
					-- In packet only one RR is stored per RR set structure
					-- so we can convert only first RDATA to text
					table.insert(data, string.format(
						'{"name": "%s", "type": %d, "TTL": %d, "data": "%s"}',
						rrset:owner(), rrset:type(), rrset:ttl(), rrset:tostring(0)))
				else
					table.insert(data, rrset:tostring())
				end
			end
		end
	end
	return table.concat(data, tojson and ',' or '')
end
local function packet_tostring(pkt)
	local hdr = string.format(';; ->>HEADER<<- opcode: %s; status: %s; id: %d\n',
		const_opcode_str[pkt:opcode()], const_rcode_str[pkt:rcode()], pkt:id())
	local flags = {}
	for _,v in ipairs({'rd', 'tc', 'aa', 'qr', 'cd', 'ad', 'ra'}) do
		if(pkt[v](pkt)) then table.insert(flags, v) end
	end
	local info = string.format(';; Flags: %s; QUERY: %d; ANSWER: %d; AUTHORITY: %d; ADDITIONAL: %d\n',
		table.concat(flags, ' '), pkt:qdcount(), pkt:ancount(), pkt:nscount(), pkt:arcount())
	local data = '\n'
	if pkt.opt ~= nil then
		local opt = pkt.opt
		-- Append DNS COOKIE information
		local cookie = edns_option(opt, const_opt.COOKIE)
		if cookie then
			local hex = ''
			cookie:gsub('.', function (c) hex = hex .. string.format('%02X',string.byte(c)) end)
			cookie = '; cookie: ' .. hex
		end
		-- Finalize OPT pseudo-section
		data = data..string.format(';; OPT PSEUDOSECTION:\n; EDNS: version: %d, flags:%s; udp: %d%s\n',
			edns_version(opt), edns_do(opt) and ' do' or '', edns_payload(opt), cookie or '')
	end
	if pkt.tsig ~= nil then
		data = data..string.format(';; TSIG PSEUDOSECTION:\n%s', pkt.tsig:tostring())
	end
	local qtype = pkt:qtype()
	-- Zone transfer answers may omit question
	if pkt:qdcount() > 0 then
		data = data..string.format(';; QUESTION\n;%s\t%s\t%s\n',
			pkt:qname(), const_type_str[pkt:qtype()], const_class_str[pkt:qclass()])
	end
	local data_sec = {}
	for i = const_section.ANSWER, const_section.ADDITIONAL do
		table.insert(data_sec, section_tostring(pkt, i))
	end
	return hdr..info..data..table.concat(data_sec, '')
end
local function packet_tojson(pkt)
	local data = {}
	-- Serialise header
	table.insert(data, string.format('"Status": %d,"TC": %s,"RD": %s, "RA": %s, "AD": %s,"CD": %s',
		pkt:rcode(), pkt:tc(), pkt:rd(), pkt:ra(), pkt:ad(), pkt:cd()))
	-- Optional question
	if pkt:qdcount() > 0 then
		table.insert(data, string.format('"Question":[{"name": "%s", "type": %d}]', pkt:qname(), pkt:qtype()))
	end
	-- Record sections
	for i = const_section.ANSWER, const_section.ADDITIONAL do
		local res = section_tostring(pkt, i, 'json')
		if #res > 0 then
			res = string.format('"%s":[%s]', const_section_str_lower[i], res)
			table.insert(data, res)
		end
	end
	return string.format('{%s}', table.concat(data, ','))
end
-- RR insertion doesn't copy RR and is opaque to LuaJIT GC, we must track RRs that packet touched
local pkt_refs = {}
local function pkt_ref(pkt, rr) return table.insert(pkt_refs, {ffi.cast(void_p, pkt), rr}) end
local function pkt_unref(pkt)
	local pkt_p = ffi.cast(void_p, pkt)
	for i, v in ipairs(pkt_refs) do
		if v[1] == pkt_p then pkt_refs[i] = nil end
	end
end
local pkt_arr = ffi.new('knot_pkt_t *[1]')
local function pkt_free(pkt)
	pkt_unref(pkt)
	pkt_arr[0] = pkt
	knot.knot_pkt_free(pkt_arr)
end
ffi.metatype( knot_pkt_t, {
	__new = function (ctype, size, wire)
		if size < 12 or size >= 65536 then error('packet size must be <12, 65535>') end
		local pkt = knot.knot_pkt_new(nil, size, nil)
		if pkt == nil then return nil end
		if wire == nil then
			pkt:id(math.random(0, 65535))
		else
			assert(size <= #wire)
			ffi.copy(pkt.wire, wire, size)
			pkt.size = size
			pkt.parsed = 0
		end
		return ffi.gc(pkt[0], pkt_free)
	end,
	__tostring = function(pkt)
		return pkt:tostring(false)
	end,
	__len = function(pkt)
		assert(pkt ~= nil) return pkt.size
	end,
	__ipairs = function(self)
		return ipairs(self:section(const_section.ANSWER))
	end,
	__index = {
		-- Header
		id      = function(pkt, val) return pkt_cnt(pkt, 0,  val) end,
		qdcount = function(pkt, val) return pkt_cnt(pkt, 4,  val) end,
		ancount = function(pkt, val) return pkt_cnt(pkt, 6,  val) end,
		nscount = function(pkt, val) return pkt_cnt(pkt, 8,  val) end,
		arcount = function(pkt, val) return pkt_cnt(pkt, 10, val) end,
		opcode = function (pkt, val)
			assert(pkt ~= nil)
			pkt.wire[2] = (val) and bit.bor(bit.band(pkt.wire[2], 0x78), 8 * val) or pkt.wire[2]
			return (bit.band(pkt.wire[2], 0x78) / 8)
		end,
		rcode = function (pkt, val)
			assert(pkt ~= nil)
			-- RFC6891 6.1.3 -- extended RCODE forms the upper 8 bits of whole
			-- 12-bit RCODE (together with the 4 bits of 'normal' RCODE).
			if val then
				if val > 0x0f then
					assert(pkt.opt ~= nil, 'cannot use extended without OPT in packet')
					local upper = bit.rshift(val, 4)
					knot.knot_edns_set_ext_rcode(pkt.opt, upper)
				end
				pkt.wire[3] = bit.bor(bit.band(pkt.wire[3], 0xf0), val)
			end
			local ret = bit.band(pkt.wire[3], 0x0f)
			-- Add extended RCODE if OPT is present
			if pkt.opt ~= nil then
				ret = bit.bor(ret, bit.lshift(knot.knot_edns_get_ext_rcode(pkt.opt), 4))
			end
			return ret
		end,
		rd = function (pkt, val) return pkt_flags(pkt, 2, 0x01, val) end,
		tc = function (pkt, val) return pkt_flags(pkt, 2, 0x02, val) end,
		aa = function (pkt, val) return pkt_flags(pkt, 2, 0x04, val) end,
		qr = function (pkt, val) return pkt_flags(pkt, 2, 0x80, val) end,
		cd = function (pkt, val) return pkt_flags(pkt, 3, 0x10, val) end,
		ad = function (pkt, val) return pkt_flags(pkt, 3, 0x20, val) end,
		ra = function (pkt, val) return pkt_flags(pkt, 3, 0x80, val) end,
		-- Question
		qname = function(pkt)
			if pkt.qname_size <= 0 then return nil end
			-- QNAME is sanitised at this point via parse()
			return ffi.cast('knot_dname_t *', pkt.wire + 12)[0]
		end,
		qclass = function(pkt) return (knot.knot_pkt_qclass(pkt)) end,
		qtype  = function(pkt) return (knot.knot_pkt_qtype(pkt)) end,
		-- Sections
		empty = function (pkt)
			return (pkt.rrset_count == 0)
		end,
		question = function (pkt, owner, rtype, rclass)
			assert(pkt ~= nil)
			if rclass == nil then rclass = const_class.IN end
			if pkt.rrset_count > 0 then error("packet must be empty to insert question") end
			if not ffi.istype(knot_dname_t, owner) then owner = knot_dname_t(owner) end
			return (knot.knot_pkt_put_question(pkt, owner, rclass, rtype) == 0)
		end,
		section = function (pkt, section_id)
			assert(pkt ~= nil)
			if section_id == nil then return pkt.cur_section end
			local s = knot.knot_pkt_section(pkt, section_id)
			assert(s ~= nil)
			return s[0]
		end,
		put = function (pkt, rrset, noref, compr)
			-- Insertion loses track of rrset reference, reference it explicitly
			if pkt == nil or rrset == nil or rrset:owner() == nil then return false end
			if noref ~= true then
				pkt_ref(pkt, rrset)
				if rrset:type() == const_type.OPT then pkt.opt = rrset end
			end
			local ret = knot.knot_pkt_put(pkt, compr or 0, rrset, 0)
			if ret == 0 then
				pkt.parsed = pkt.size
				return true
			else return false end
		end,
		-- Packet manipulation
		parse_question = function (pkt)
			assert(pkt ~= nil)
			local ret = knot.knot_pkt_parse_question(pkt)
			if ret ~= 0 then return nil, strerr(ret) end
			return true
		end,
		parse_section = function (pkt, section)
			assert(pkt ~= nil)
			pkt:begin(section)
			local ret = knot.knot_pkt_parse_section(pkt, 0)
			if ret ~= 0 then return nil, strerr(ret) end
			return true
		end,
		parse = function (pkt, strip_edns)
			-- Keep TSIG on wire for packets, as packet parser strips it
			-- @note this is a workaround for libknot quirk, where the TSIG RR is on the wire
			--       for outgoing packets, but is stripped from incoming packets
			-- @note 'parsed' represents size without TSIG, 'size' will include TSIG
			assert(pkt ~= nil)
			local keep_size = pkt.size
			local ret = knot.knot_pkt_parse(pkt, 0)
			if ret == 0 then
				pkt.size = keep_size
				if pkt.tsig ~= nil then pkt:arcount(pkt:arcount() + 1) end
				-- Strip EDNS from wire if asked to
				if pkt.opt ~= nil and strip_edns then
					local opt_len = knot.knot_edns_wire_size(pkt.opt)
					pkt.size = pkt.size - opt_len
					pkt.parsed = pkt.parsed - opt_len
					pkt:arcount(pkt:arcount() - 1)
				end
				return true
			else return false, ret end
		end,
		begin = function (pkt, section)
			assert(pkt ~= nil)
			assert(section >= pkt:section(), "cannot write to finished section")
			return (knot.knot_pkt_begin(pkt, section))
		end,
		copy = function (pkt)
			assert(pkt ~= nil)
			local dst = knot_pkt_t(pkt.max_size)
			ffi.copy(dst.wire, pkt.wire, pkt.size)
			dst.size = pkt.size
			return dst:parse() and dst or nil
		end,
		clear = function (pkt)
			pkt_unref(pkt)
			return (knot.knot_pkt_clear(pkt))
		end,
		towire = function (pkt)
			return ffi.string(pkt.wire, pkt.size)
		end,
		tostring = function(pkt, short)
			if short == true then
				return section_tostring(pkt, const_section.ANSWER, true)
			elseif short == 'json' then
				return packet_tojson(pkt)
			else
				return packet_tostring(pkt)
			end
		end,
		answers = function (pkt, query)
			return pkt:qr() and pkt:id() == query:id() and pkt:qclass() == query:qclass()
			       and pkt:qtype() == query:qtype() and pkt:qname() == query:qname()
		end,
		toanswer = function (pkt, answer)
			assert(answer.max_size >= pkt.size)
			assert(pkt ~= answer)
			answer:clear()
			if pkt:qdcount() > 0 then
				assert(answer:question(pkt:qname(), pkt:qtype(), pkt:qclass()))
			end
			answer:id(pkt:id())
			answer:qr(true)
			return true
		end,
	},
})

-- TSIG metatype
local tsig_t = ffi.typeof('tsig_t')
ffi.metatype( tsig_t, {
	__gc = function (tsig)
		knot.knot_tsig_key_deinit(tsig.key)
	end,
	__new = function (ct, text)
		assert(text)
		local tsig = ffi.new(tsig_t)
		local ret = knot.knot_tsig_key_init_str(tsig.key, text)
		if ret ~= 0 then return nil end
		return tsig
	end,
	__index = {
		sign = function (tsig, pkt, rcode)
			assert(tsig)
			assert(pkt)
			-- Attempt to sign with TSIG key
			if rcode == nil then rcode = 0 end
			-- Strip previous TSIG from signed answer
			if pkt.tsig ~= nil then pkt:arcount(pkt:arcount() - 1) end
			pkt.tsig = nil
			-- Sign the query/response including previous digest
			local newlen = ffi.new('size_t [?]', 2, {0, pkt.parsed})
			local ret = knot.knot_tsig_sign(pkt.wire, newlen + 1, pkt.max_size, tsig.digest, tsig.digest_len,
			                                tsig.digest, newlen, tsig.key, rcode, tsig.last_signed)
			if ret ~= 0 then return false end
			pkt.size = newlen[1]
			-- Reparse TSIG RR from wire to make it visible, --> this is dangerous <--
			-- @note knot_rrset_rr_from_wire corrupts the stack, probably requires too much stackspace
			local rrset = knot_rrset_t(tsig.key.name, const_type.TSIG, const_class.ANY)
			local rr_len = pkt.size - pkt.parsed
			-- Skip owner/u16 type/u16 class/u32 ttl/u16 rdlen
			local wire_skip = #tsig.key.name + 10
			rrset:add(pkt.wire + pkt.parsed + wire_skip, 0, rr_len - wire_skip)
			pkt.tsig = rrset
			pkt_ref(pkt, rrset)
			tsig.digest_len = newlen[0]
			tsig.last_signed = knot.knot_tsig_rdata_time_signed(pkt.tsig)
			return true
		end,
		verify = function (tsig, pkt)
			assert(tsig)
			assert(pkt)
			assert(pkt.tsig)
			-- Strip TSIG from wire
			local old_arcount = pkt:arcount()
			pkt:arcount(old_arcount - 1)
			local ret = knot.knot_tsig_client_check(pkt.tsig, pkt.wire, pkt.parsed,
			                                        tsig.digest, tsig.digest_len, tsig.key, tsig.last_signed)
			pkt:arcount(old_arcount)
			if ret ~= 0 then return const_errcode_tsig[ret] or false end
			-- Store verified signature digest
			tsig.digest_len = knot.knot_tsig_rdata_mac_length(pkt.tsig)
			tsig.last_signed = knot.knot_tsig_rdata_time_signed(pkt.tsig)
			ffi.copy(tsig.digest, knot.knot_tsig_rdata_mac(pkt.tsig), tsig.digest_len)
			return true
		end,
		copy = function (tsig)
			local copy = tsig_t()
			if not copy or knot.knot_tsig_key_copy(copy.key, tsig.key) ~= 0 then return nil end
			return copy
		end,
	},
})

-- Module API
local M = {
	-- Constants
	class = const_class,
	type = const_type,
	section = const_section,
	opcode = const_opcode,
	rcode = const_rcode,
	rcode_tsig = const_rcode_tsig,
	option = const_opt,
	tostring = {
		class = const_class_str,
		type = const_type_str,
		section = const_section_str,
		opcode = const_opcode_str,
		rcode = const_rcode_str,
		rcode_tsig = const_rcode_tsig_str,
		option = const_opt_str,
	},
	-- Types
	dname = knot_dname_t,
	rdata = rdata,
	rrset = knot_rrset_t,
	packet = knot_pkt_t,
	edns = {
		init = edns_init,
		rrset = edns_t,
		version = edns_version,
		payload = edns_payload,
		dobit = edns_do,
		flags = edns_flags,
		has = edns_hasoption,
		option = edns_option,
	},
	tsig = tsig_t,
	-- Metatypes
	todname = function (udata) return ffi.cast('knot_dname_t *', udata) end,
	tordata = function (udata) return ffi.cast('knot_rdata_t *', udata) end,
	torrset = function (udata) return ffi.cast('knot_rrset_t *', udata) end,
	topacket = function (udata) return ffi.cast('knot_pkt_t *', udata) end,
	-- Utils
	strerr = strerr,
	hexdump = utils.hexdump,
	utils = utils,
}

return M
