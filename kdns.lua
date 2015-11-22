-- LuaJIT ffi bindings for libkres, a DNS resolver library.
-- @note Since it's statically compiled, it expects to find the symbols in the C namespace.

local ffi = require('ffi')
local bit = require('bit')
local math = require('math')
local random = math.random
local bor = bit.bor
local band = bit.band
local C = ffi.C
local utils = require('kdns.utils')
local n16 = utils.n16
local n32 = utils.n32
local knot = ffi.load(utils.dll_versioned('libknot', '1'))
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
	knot_dname_t *_owner; /* This is private because GC-unaware */
	uint16_t _type;
	uint16_t _class;
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
bool knot_dname_in(const knot_dname_t *domain, const knot_dname_t *sub);
/* resource records */
extern const knot_dump_style_t KNOT_DUMP_STYLE_DEFAULT;
uint16_t knot_rdata_rdlen(const knot_rdata_t *rr);
uint8_t *knot_rdata_data(const knot_rdata_t *rr);
knot_rdata_t *knot_rdataset_at(const knot_rdataset_t *rrs, size_t pos);
void knot_rdata_set_ttl(knot_rdata_t *rr, uint32_t ttl);
uint32_t knot_rrset_ttl(const knot_rrset_t *rrset);
int knot_rrset_txt_dump(const knot_rrset_t *rrset, char *dst, size_t maxlen, const knot_dump_style_t *style);
int knot_rrset_add_rdata(knot_rrset_t *rrset, const uint8_t *rdata, const uint16_t size, const uint32_t ttl, void *mm);
knot_rrset_t *knot_rrset_new(const knot_dname_t *owner, uint16_t type, uint16_t rclass, void *mm);
knot_rrset_t *knot_rrset_copy(const knot_rrset_t *src, void *mm);
void knot_rrset_free(knot_rrset_t **rrset, void *mm);
/* opt rr */
uint8_t knot_edns_get_version(const knot_rrset_t *opt_rr);
void knot_edns_set_version(knot_rrset_t *opt_rr, uint8_t version);
int knot_edns_add_option(knot_rrset_t *opt_rr, uint16_t code, uint16_t length, const uint8_t *data, void *mm);
bool knot_edns_has_option(const knot_rrset_t *opt_rr, uint16_t code);
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
int knot_pkt_parse(knot_pkt_t *pkt, unsigned flags);
int knot_pkt_copy(knot_pkt_t *dst, const knot_pkt_t *src);
void knot_pkt_clear(knot_pkt_t *pkt);
void knot_pkt_free(knot_pkt_t **pkt);
]]

-- Basic types
local void_p = ffi.typeof('void *')
local u16_p = ffi.typeof('uint16_t *')
local int_t = ffi.typeof('int')
local i8_vla = ffi.typeof('char [?]')
local u8_vla = ffi.typeof('uint8_t [?]')

-- Constants
local const_class = ffi.new('struct rr_class')
local const_type = ffi.new('struct rr_type')
local const_section = ffi.new('struct pkt_section')
local const_opcode = ffi.new('struct pkt_opcode')
local const_rcode = ffi.new('struct pkt_rcode')

-- Meta tables for catchall
local meta_nokey = { __index = function (t, k) return nil end }
ffi.metatype('struct rr_class', meta_nokey)
ffi.metatype('struct rr_type', meta_nokey)

-- Constant tables
local const_class_str = {
	[1] = 'IN', [3] = 'CH', [254] = 'NONE', [255] = 'ANY'
}
local function const_type_convert(rtype)
	local str = ffi.new(i8_vla, 16)
	knot.knot_rrtype_to_string(rtype, str, 16)
	return ffi.string(str)
end
local const_type_str = {}
setmetatable(const_type_str, { __index = function (t, k) return const_type_convert(k) end })
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
local dname_buf = ffi.new(u8_vla, 256)
local knot_dname_t = ffi.typeof('knot_dname_t')
ffi.metatype( knot_dname_t, {
	__tostring = function(dname)
		return ffi.string(knot.knot_dname_to_str(dname_buf, dname, 256))
	end,
	__len = function(dname)
		return knot.knot_dname_size(dname)
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
		within = function(dname, parent)
			if type(parent) == 'string' then parent = knot_dname_t(parent) end
			return knot.knot_dname_in(parent, dname)
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
local rrparser = require('kdns.rrparser')
local function rd_parse (rdata_str)
	local parser = rrparser.new()
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
local function rrset_free(rr)
	knot.knot_rrset_free(ffi.new("knot_rrset_t *[1]", rr), nil)
end
local rrset_buflen = (64 + 1) * 1024
local rrset_buf = ffi.new(i8_vla, rrset_buflen)
local knot_rrset_t = ffi.typeof('knot_rrset_t')
ffi.metatype( knot_rrset_t, {
	__new = function (ct, owner, type, class)
		if class == nil then class = const_class.IN end
		if not ffi.istype(knot_dname_t, owner) then owner = knot_dname_t(owner) end
		return ffi.gc(knot.knot_rrset_new(owner, type, class, nil), rrset_free)
	end,
	__len = function(rr) return rr.rr.count end,
	__tostring = function(rr)
		local ret = 0
		local style = knot.KNOT_DUMP_STYLE_DEFAULT
		if rr.rr.count > 0 then
			ret = knot.knot_rrset_txt_dump(rr, rrset_buf, rrset_buflen, style)
			if ret < 0 then return nil end
			return ffi.string(rrset_buf)
		else
			return string.format('%s\t%s\t%s', rr:owner(), const_class_str[rr:class()], const_type_str[rr:type()])
		end
	end,
	__index = {
		owner = function(rr) return rr._owner end,
		type = function(rr) return rr._type end,
		class = function(rr) return rr._class end,
		ttl = function(rr, ttl)
			if rr.rr.count > 0 then
				if ttl ~= nil then
					local rd = knot.knot_rdataset_at(rr.rr, 0)
					knot.knot_rdata_set_ttl(rd, ttl)
				end
				return tonumber(knot.knot_rrset_ttl(rr))
			else return 0 end
		end,
		rdata = function(rr, i)
			local rdata = knot.knot_rdataset_at(rr.rr, i)
			return ffi.string(knot.knot_rdata_data(rdata), knot.knot_rdata_rdlen(rdata))
		end,
		get = function(rr, i)
			return {owner = rr:owner(),
			        ttl = rr:ttl(),
			        class = tonumber(rr:class()),
			        type = tonumber(rr:type()),
			        rdata = rr:rdata(i)}
		end,
		add = function(rr, rdata, ttl)
			if ttl == nil then ttl = rr:ttl() end
			local ret = knot.knot_rrset_add_rdata(rr, rdata, #rdata, ttl, nil)
			return ret == 0 and rr or nil
		end,
		copy = function (rr)
			return ffi.gc(knot.knot_rrset_copy(rr, nil), rrset_free)
		end,
	},
	__newindex = function (rr, k, v) error("rrset is immutable") end,
})

-- Functions for OPT RR
local function edns_version(rr, val)
	if val ~= nil then knot.knot_edns_set_version(rr, val) end
	return knot.knot_edns_get_version(rr)
end
local function edns_payload(rr, val)
	if val ~= nil then rr._class = val end
	return rr:class()
end
local function edns_do(rr, val)
	local ttl = rr:ttl()
	if val ~= nil then
		ttl = bor(ttl, val and 0x8000 or 0x00)
		rr:ttl(ttl)
	end
	return band(ttl, 0x8000) ~= 0
end
local function edns_option(rr, code, val)
	if val ~= nil then knot.knot_edns_add_option(rr, code, #val, val, nil) end
	return knot.knot_edns_has_option(rr, code)
end
local function edns_t(version, payload)
	if version == nil then version = 0 end
	if payload == nil then payload = 4096 end
	local rr = knot_rrset_t('\0', const_type.OPT, payload)
	if rr then
		rr:add('', 0)
		edns_version(rr, version)
	end
	return rr
end

-- Metatype for packet
local knot_pkt_t = ffi.typeof('knot_pkt_t')
local function pkt_cnt(pkt, off)
	local ptr = ffi.cast(u16_p, pkt.wire + off)
	return n16(ptr[0])
end
local function pkt_flags(pkt, idx, off, val)
	pkt.wire[idx] = bor(pkt.wire[idx], (val) and off or 0x00)
	return band(pkt.wire[idx], off) ~= 0
end
-- RR insertion doesn't copy RR and is opaque to LuaJIT GC, we must track RRs that packet touched
local pkt_refs = {}
local function pkt_ref(pkt, rr) return table.insert(pkt_refs, {ffi.cast(void_p, pkt), rr}) end
local function pkt_unref(pkt)
	for i, v in ipairs(pkt_refs) do
		if v[1] == ffi.cast(void_p, pkt) then pkt_refs[i] = nil end
	end
end
local function pkt_free(pkt)
	knot.knot_pkt_free(ffi.new("knot_pkt_t *[1]", pkt))
end
ffi.metatype( knot_pkt_t, {
	__new = function (ctype, size, wire)
		if wire ~= nil then
			size = math.min(#wire, size)
			wire = ffi.cast(void_p, wire)
		end
		local pkt = ffi.gc(knot.knot_pkt_new(wire, size, nil), pkt_free)
		if pkt ~= nil and wire == nil then pkt:id(random(0, 65535)) end
		return pkt
	end,
	__tostring = function(pkt)
		local hdr = string.format(';; ->>HEADER<<- opcode: %s; status: %s; id: %d\n',
			const_opcode_str[pkt:opcode()], const_rcode_str[pkt:rcode()], pkt:id())
		local flags = {}
		for k,v in pairs({'rd', 'tc', 'aa', 'qr', 'cd', 'ad', 'ra'}) do
			if(pkt[v](pkt)) then table.insert(flags, v) end
		end
		local info = string.format(';; Flags: %s; QUERY: %d; ANSWER: %d; AUTHORITY: %d; ADDITIONAL: %d\n',
			table.concat(flags, ' '), pkt:qdcount(), pkt:ancount(), pkt:nscount(), pkt:arcount())
		local data = '\n'
		if pkt.opt ~= nil then
			local opt = pkt.opt
			data = data..string.format(';; OPT PSEUDOSECTION:\n; EDNS: version: %d, flags:%s; udp: %d\n',
				edns_version(opt), edns_do(opt) and ' do' or '', edns_payload(opt))
		end
		if pkt:qdcount() > 0 then
			data = data..string.format(';; QUESTION\n;%s\t%s\t%s\n',
				tostring(knot_dname_t(pkt:qname())), const_type_str[pkt:qtype()], const_class_str[pkt:qclass()])
		end
		for i = const_section.ANSWER, const_section.ADDITIONAL do
			local section = knot.knot_pkt_section(pkt, i)
			if section.count > 0 then
				data = data..string.format(';; %s\n', const_section_str[i])
				for j = 0, section.count - 1 do
					local rrset = knot.knot_pkt_rr(section, j)
					local rrtype = rrset:type()
					if rrtype ~= const_type.OPT and rrtype ~= const_type.TSIG then
						data = data..tostring(rrset)
					end
				end
			end
		end
		return hdr..info..data
	end,
	__len = function(pkt)
		return pkt.size
	end,
	__index = {
		-- Header
		id = function (pkt, val)
			local id_wire = ffi.cast(u16_p, pkt.wire)
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
		rd = function (pkt, val) return pkt_flags(pkt, 2, 0x01, val) end,
		tc = function (pkt, val) return pkt_flags(pkt, 2, 0x02, val) end,
		aa = function (pkt, val) return pkt_flags(pkt, 2, 0x04, val) end,
		qr = function (pkt, val) return pkt_flags(pkt, 2, 0x80, val) end,
		cd = function (pkt, val) return pkt_flags(pkt, 3, 0x10, val) end,
		ad = function (pkt, val) return pkt_flags(pkt, 3, 0x20, val) end,
		ra = function (pkt, val) return pkt_flags(pkt, 3, 0x80, val) end,
		-- Question
		qname = function(pkt)
			local qname = knot.knot_pkt_qname(pkt)
			if qname == nil then return nil end
			return ffi.string(qname, knot.knot_dname_size(qname))
		end,
		qclass = function(pkt) return knot.knot_pkt_qclass(pkt) end,
		qtype  = function(pkt) return knot.knot_pkt_qtype(pkt) end,
		-- Sections
		question = function (pkt, owner, rtype, rclass)
			if rclass == nil then rclass = const_class.IN end
			if pkt.rrset_count > 0 then error("packet must be empty to insert question") end
			if type(owner) == 'string' then owner = knot_dname_t(owner) end
			return knot.knot_pkt_put_question(pkt, owner, rclass, rtype) == 0
		end,
		section = function (pkt, section_id)
			if section_id == nil then
				-- Old version of libknot didn't have 'tsig_wire' struct
				-- check if it overlaps with pkt._current, in this case
				-- the pointer would be <= 2 and the len ~= 0
				local cur = ffi.cast(int_t, pkt._tsig_wire.pos)
				if cur <= 2 and pkt._tsig_wire.len ~= 0 then return cur
				else return pkt._current end
			end
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
		put = function (pkt, rrset, noref)
			-- Insertion loses track of rrset reference, reference it explicitly
			if noref ~= true then pkt_ref(pkt, rrset) end
			if rrset:type() == const_type.OPT then pkt.opt = rrset end
			return knot.knot_pkt_put(pkt, 0, rrset, 0) == 0
		end,
		-- Packet manipulation
		parse = function (pkt, wire)
			return knot.knot_pkt_parse(pkt, 0) == 0
		end,
		begin = function (pkt, section)
			if section >= pkt:section() then 
				return knot.knot_pkt_begin(pkt, section)
			else
				error("cannot write to finished section")
			end
		end,
		copy = function (pkt)
			local dst = knot_pkt_t(#pkt)
			return knot.knot_pkt_copy(dst, pkt) == 0 and dst or nil
		end,
		clear = function (pkt)
			return knot.knot_pkt_clear(pkt)
		end,
		towire = function (pkt)
			return ffi.string(pkt.wire, pkt.size)
		end,
		answers = function (pkt, query)
			return pkt:qr() and pkt:id() == query:id() and pkt:qclass() == query:qclass()
			       and pkt:qtype() == query:qtype() and pkt:qname() == query:qname()
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
	tostring = {
		class = const_class_str,
		type = const_type_str,
		section = const_section_str,
		opcode = const_opcode_str,
		rcode = const_rcode_str,
	},
	-- Types
	dname = knot_dname_t,
	rdata = rdata,
	rrset = knot_rrset_t,
	packet = knot_pkt_t,
	edns = {
		rrset = edns_t,
		version = edns_version,
		payload = edns_payload,
		dobit = edns_do,
		option = edns_option,
	},
	-- Metatypes
	todname = function (udata) return ffi.cast('knot_dname_t *', udata) end,
	torrset = function (udata) return ffi.cast('knot_rrset_t *', udata) end,
	topacket = function (udata) return ffi.cast('knot_pkt_t *', udata) end,
	-- Utils
	hexdump = require('kdns.utils').hexdump,
	io = require('kdns.io'),
}

return kdns
