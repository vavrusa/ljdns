-- LuaJIT ffi bindings for libkres, a DNS resolver library.
-- @note Since it's statically compiled, it expects to find the symbols in the C namespace.

local ffi = require('ffi')
local bit = require('bit')
local bor = bit.bor
local band = bit.band
local C = ffi.C
local knot = ffi.load(require('kdns.utils').dll_versioned('libknot', '1'))
ffi.cdef[[

/*
 * Record types and classes.
 */
struct rr_class {
	static const int IN         =   1;
	static const int CH         =   3;
	static const int NONE       = 254;
	static const int ANY        = 255;
};
struct rr_type {
	static const int A          =   1;
	static const int NS         =   2;
	static const int CNAME      =   5;
	static const int SOA        =   6;
	static const int PTR        =  12;
	static const int HINFO      =  13;
	static const int MINFO      =  14;
	static const int MX         =  15;
	static const int TXT        =  16;
	static const int RP         =  17;
	static const int AFSDB      =  18;
	static const int RT         =  21;
	static const int SIG        =  24;
	static const int KEY        =  25;
	static const int AAAA       =  28;
	static const int LOC        =  29;
	static const int SRV        =  33;
	static const int NAPTR      =  35;
	static const int KX         =  36;
	static const int CERT       =  37;
	static const int DNAME      =  39;
	static const int OPT        =  41;
	static const int APL        =  42;
	static const int DS         =  43;
	static const int SSHFP      =  44;
	static const int IPSECKEY   =  45;
	static const int RRSIG      =  46;
	static const int NSEC       =  47;
	static const int DNSKEY     =  48;
	static const int DHCID      =  49;
	static const int NSEC3      =  50;
	static const int NSEC3PARAM =  51;
	static const int TLSA       =  52;
	static const int CDS        =  59;
	static const int CDNSKEY    =  60;
	static const int SPF        =  99;
	static const int NID        = 104;
	static const int L32        = 105;
	static const int L64        = 106;
	static const int LP         = 107;
	static const int EUI48      = 108;
	static const int EUI64      = 109;
	static const int TKEY       = 249;
	static const int TSIG       = 250;
	static const int IXFR       = 251;
	static const int AXFR       = 252;
	static const int ANY        = 255;
};
struct pkt_section {
	static const int ANSWER     = 0;
	static const int AUTHORITY  = 1;
	static const int ADDITIONAL = 2;	
};
struct pkt_opcode {
	static const int QUERY      = 0;
	static const int IQUERY     = 1;
	static const int STATUS     = 2;
	static const int NOTIFY     = 4;
	static const int UPDATE     = 5;
};
struct pkt_rcode {
	static const int NOERROR    =  0;
	static const int FORMERR    =  1;
	static const int SERVFAIL   =  2;
	static const int NXDOMAIN   =  3;
	static const int NOTIMPL    =  4;
	static const int REFUSED    =  5;
	static const int YXDOMAIN   =  6;
	static const int YXRRSET    =  7;
	static const int NXRRSET    =  8;
	static const int NOTAUTH    =  9;
	static const int NOTZONE    = 10;
	static const int BADVERS    = 16;
};

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
typedef struct { uint8_t bytes[]; } knot_dname_t;
typedef uint8_t knot_rdata_t;
typedef struct knot_rdataset {
	uint16_t count;
	knot_rdata_t *data;
} knot_rdataset_t;
typedef struct knot_rrset {
	knot_dname_t *owner;
	uint16_t type;
	uint16_t class;
	knot_rdataset_t rr;
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
	knot_section_t _current;
	knot_pktsection_t _sections[3];
	size_t _rrset_allocd;
	knot_rrinfo_t *_rr_info;
	knot_rrset_t *_rr;
	uint8_t _stub[]; /* Do not touch */
} knot_pkt_t;

/* libc */
void free(void *ptr);
/* descriptors */
int knot_rrtype_to_string(uint16_t rrtype, char *out, size_t out_len);
/* domain names */
bool knot_dname_is_equal(const knot_dname_t *d1, const knot_dname_t *d2);
int knot_dname_size(const knot_dname_t *name);
knot_dname_t *knot_dname_from_str(uint8_t *dst, const char *name, size_t maxlen);
char *knot_dname_to_str(char *dst, const knot_dname_t *name, size_t maxlen);
int knot_dname_to_lower(knot_dname_t *name);
int knot_dname_labels(const uint8_t *name, const uint8_t *pkt);
/* resource records */
extern const knot_dump_style_t KNOT_DUMP_STYLE_DEFAULT;
void knot_rdata_init(knot_rdata_t *rdata, uint16_t rdlen, const uint8_t *data, uint32_t ttl);
uint16_t knot_rdata_rdlen(const knot_rdata_t *rr);
uint8_t *knot_rdata_data(const knot_rdata_t *rr);
size_t knot_rdata_array_size(uint16_t size);
size_t knot_rdataset_size(const knot_rdataset_t *rrs);
knot_rdata_t *knot_rdataset_at(const knot_rdataset_t *rrs, size_t pos);
uint32_t knot_rrset_ttl(const knot_rrset_t *rrset);
int knot_rrset_txt_dump(const knot_rrset_t *rrset, char *dst, size_t maxlen, const knot_dump_style_t *style);
/* packet */
const knot_dname_t *knot_pkt_qname(const knot_pkt_t *pkt);
uint16_t knot_pkt_qtype(const knot_pkt_t *pkt);
uint16_t knot_pkt_qclass(const knot_pkt_t *pkt);
int knot_pkt_begin(knot_pkt_t *pkt, int section_id);
const knot_rrset_t *knot_pkt_rr(const knot_pktsection_t *section, uint16_t i);
const knot_pktsection_t *knot_pkt_section(const knot_pkt_t *pkt, knot_section_t section_id);
knot_pkt_t *knot_pkt_new(void *wire, uint16_t len, /* mm_ctx_t */ void *mm);
int knot_pkt_put(knot_pkt_t *pkt, uint16_t compr_hint, const knot_rrset_t *rr, uint16_t flags);
int knot_pkt_put_question(knot_pkt_t *pkt, const knot_dname_t *qname,
                          uint16_t qclass, uint16_t qtype);
void knot_pkt_clear(knot_pkt_t *pkt);
void knot_pkt_free(knot_pkt_t **pkt);
]]

-- Constants
local const_class = ffi.new('struct rr_class')
local const_type = ffi.new('struct rr_type')
local const_section = ffi.new('struct pkt_section')
local const_opcode = ffi.new('struct pkt_opcode')
local const_rcode = ffi.new('struct pkt_rcode')

-- Constant tables
local const_class_str = {
	[1] = 'IN', [3] = 'CH', [254] = 'NONE', [255] = 'ANY'
}
local function const_type_str(rtype)
	local str = ffi.new('char [?]', 16)
	knot.knot_rrtype_to_string(rtype, str, 16)
	return ffi.string(str)
end
local const_rcode_str = {
	[0] = 'NOERROR', [1] = 'FORMERR', [2] = 'SERVFAIL', [3] = 'NXDOMAIN',
	[4] = 'NOTIMPL', [5] = 'REFUSED', [6] = 'YXDOMAIN', [7] = 'YXRRSET',
	[8] = 'NXRRSET', [9] = 'NOTAUTH', [10] = 'NOTZONE', [16] = 'BADVERS'
}
local const_opcode_str = {
	[0] = 'QUERY', [1] = 'IQUERY', [2] = 'STATUS', [4] = 'NOTIFY', [5] = 'UPDATE'
}
local const_section_str = {
	[0] = 'ANSWER', [1] = 'AUTHORITY', [2] = 'ADDITIONAL',
}

-- Metatype for domain name
local knot_dname_t = ffi.typeof('knot_dname_t')
ffi.metatype( knot_dname_t, {
	__tostring = function(dname)
		return ffi.string(ffi.gc(knot.knot_dname_to_str(nil, dname, 0), C.free))
	end,
	__index = {
		parse = function(name)
			return ffi.gc(knot.knot_dname_from_str(nil, name, 0), C.free)
		end,
		lower = function(name)
			if type(name) == 'string' then name = knot_dname_t(name) end
			knot.knot_dname_to_lower(name)
			return name
		end,
		labels = function(name)
			if type(name) == 'string' then name = knot_dname_t(name) end
			return knot.knot_dname_labels(name.bytes, nil)
		end,
	},
	__eq = function(a, b)
		if b == nil then return false
		elseif type(b) == 'string' then b = knot_dname_t(b)
		elseif type(b) ~= 'cdata' then return false
		end
		return knot.knot_dname_is_equal(a, b)
	end,
})

-- RDATA parser
local function rd_parse (rdata_str)
	local parser = require('rrparser').parser()
	if parser:read('. 0 IN '..rdata_str..'\n') == 0 then
		return ffi.string(parser.r_data, parser.r_data_length)
	else return nil end
end

-- Metatype for RDATA
local rdata = {
	parse = rd_parse,
	-- Selected types / pure parsers
	a = function (rdata_str) return rd_parse('A '..rdata_str) end,
	aaaa = function (rdata_str) return rd_parse('AAAA '..rdata_str) end,
	mx = function (rdata_str) return rd_parse('MX '..rdata_str) end,
	soa = function (rdata_str) return rd_parse('SOA '..rdata_str) end,
	ns = function (rdata_str) return rd_parse('NS '..rdata_str) end,
	txt = function (rdata_str) return rd_parse('TXT '..rdata_str) end,
}

-- Metatype for RR set
local rrset_dump_buflen = (64 + 1) * 1024
local rrset_dump_buf = ffi.new('char [?]', rrset_dump_buflen)
local knot_rrset_t = ffi.typeof('knot_rrset_t')
ffi.metatype( knot_rrset_t, {
	__tostring = function(rr)
		local ret = 0
		local style = knot.KNOT_DUMP_STYLE_DEFAULT
		if rr.rr.count > 0 then
			ret = knot.knot_rrset_txt_dump(rr, rrset_dump_buf, rrset_dump_buflen, style)
			if ret < 0 then return nil end
			return ffi.string(rrset_dump_buf)
		else
			return string.format('%s\t%s\t%s', rr.owner, const_class_str[rr.class], const_type_str(rr.type))
		end
	end,
	__index = {
		ttl = function(rr)
			return rr.rr.count > 0 and tonumber(knot.knot_rrset_ttl(rr)) or 0
		end,
		rdata = function(rr, i)
			local rdata = knot.knot_rdataset_at(rr.rr, i)
			return ffi.string(knot.knot_rdata_data(rdata), knot.knot_rdata_rdlen(rdata))
		end,
		get = function(rr, i)
			return {owner = rr.owner,
			        ttl = rr:ttl(),
			        class = tonumber(rr.class),
			        type = tonumber(rr.type),
			        rdata = rr:rdata(i)}
		end,
		add = function(rr, rdata, ttl)
			if ttl == nil then ttl = rr:ttl() end
			local old_size = knot.knot_rdataset_size(rr.rr)
			local to_add = knot.knot_rdata_array_size(#rdata)
			local new_set = ffi.new('uint8_t [?]', old_size + to_add)
			ffi.copy(new_set, rr.rr.data, old_size)
			knot.knot_rdata_init(new_set + old_size, #rdata, rdata, ttl)
			rr.rr.data = new_set
			rr.rr.count = rr.rr.count + 1
			return rr
		end,
	}
})

-- Byte order conversions
local function n32(x) return x end
local n16 = n32
if ffi.abi("le") then
	n32 = bit.bswap
	function n16(x) return bit.rshift(n32(x), 16) end
end

-- Metatype for packet
local u16p = ffi.typeof('uint16_t *')
local knot_pkt_t = ffi.typeof('knot_pkt_t')
local function pkt_cnt(pkt, off)
	local ptr = ffi.cast(u16p, pkt.wire + off)
	return n16(ptr[0])
end
local function pkt_free(pkt) knot.knot_pkt_free(ffi.new("knot_pkt_t *[1]", pkt)) end
ffi.metatype( knot_pkt_t, {
	__new = function (size)
		return ffi.gc(knot.knot_pkt_new(nil, size, nil), pkt_free)
	end,
	__tostring = function(pkt)
		local hdr = string.format(';; ->>HEADER<<- opcode: %s; status: %s; id: %d\n',
			const_opcode_str[pkt:opcode()], const_rcode_str[pkt:rcode()], pkt:id())
		local info = string.format(';; Flags: %s; QUERY: %d; ANSWER: %d; AUTHORITY: %d; ADDITIONAL: %d\n',
			flags, pkt:qdcount(), pkt:ancount(), pkt:nscount(), pkt:arcount())
		local data = string.format(';; QUESTION\n%s\t%s\t%s\n',
			tostring(pkt:qname()), const_type_str(pkt:qtype()), const_class_str[pkt:qclass()])
		for i = const_section.ANSWER, const_section.ADDITIONAL do
			local section = knot.knot_pkt_section(pkt, i)
			if section.count > 0 then
				data = data..string.format(';; %s\n', const_section_str[i])
				for j = 0, section.count - 1 do
					local rrset = knot.knot_pkt_rr(section, j)
					data = data..tostring(rrset)
				end
			end
		end
		return hdr..info..data
	end,
	__index = {
		-- Header
		id = function (pkt, val)
			local id_wire = ffi.cast(u16p, pkt.wire)
			if val ~= nil then id_wire[0] = n16(val) end
			return n16(id_wire[0])
		end,
		qdcount = function(pkt) return pkt_cnt(pkt, 4) end,
		ancount = function(pkt) return pkt_cnt(pkt, 6) end,
		nscount = function(pkt) return pkt_cnt(pkt, 8) end,
		arcount = function(pkt) return pkt_cnt(pkt, 10) end,
		opcode = function (pkt, val)
			pkt.wire[2] = (val) and bor(band(pkt.wire[2], 0x87), 8 * val) or pkt.wire[2]
			return band(pkt.wire[2], 0x87) / 8
		end,
		rcode = function (pkt, val)
			pkt.wire[3] = (val) and bor(band(pkt.wire[3], 0xf0), val) or pkt.wire[3]
			return band(pkt.wire[3], 0x0f)
		end,
		tc = function (pkt, val)
			pkt.wire[2] = bor(pkt.wire[2], (val) and 0x02 or 0x00)
			return band(pkt.wire[2], 0x02)
		end,
		-- Question
		qname = function(pkt)
			local qname = knot.knot_pkt_qname(pkt)
			return ffi.string(qname, knot.knot_dname_size(qname))
		end,
		qclass = function(pkt) return knot.knot_pkt_qclass(pkt) end,
		qtype  = function(pkt) return knot.knot_pkt_qtype(pkt) end,
		-- Sections
		section = function (pkt, section_id)
			local records = {}
			local section = knot.knot_pkt_section(pkt, section_id)
			for i = 0, section.count - 1 do
				local rrset = knot.knot_pkt_rr(section, i)
				for k = 0, rrset.rr.count - 1 do
					table.insert(records, rrset:get(k))
				end
			end
			return records
		end, 
		begin = function (pkt, section) return knot.knot_pkt_begin(pkt, section) end,
		put = function (pkt, rrset)
			return knot.knot_pkt_put(pkt, 0, rrset, 0)
		end,
		clear = function (pkt)
			return knot.knot_pkt_clear(pkt)
		end,
		question = function (pkt, owner, rtype, rclass)
			assert(rtype ~= nil)
			if rclass == nil then rclass = const_class.IN end
			if type(owner) == 'string' then owner = knot_dname_t(owner) end
			assert(pkt.rrset_count == 0)
			return knot.knot_pkt_put_question(pkt, owner, rclass, rtype)
		end,
		towire = function (pkt)
			return ffi.string(pkt.wire, pkt.size)
		end,
	},
})

-- Module API
local kdns = {
	-- Constants
	class = const_class,
	type = const_type,
	section = const_section,
	opcode = const_opcode,
	rcode = const_rcode,
	-- Types
	dname = knot_dname_t,
	rdata = rdata,
	rrset = function (owner, type, class)
		if class == nil then class = const_class.IN end
		return knot_rrset_t(knot_dname_t(owner), type, class)
	end,
	packet = knot_pkt_t,
	-- Metatypes
	todname = function (udata) return ffi.cast('knot_dname_t *', udata) end,
	torrset = function (udata) return ffi.cast('knot_rrset_t *', udata) end,
	topacket = function (udata) return ffi.cast('knot_pkt_t *', udata) end,
	-- Utils
	hexdump = require('kdns.utils').hexdump,
}

return kdns
