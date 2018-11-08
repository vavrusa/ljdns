-- A contemporary LuaJIT DNS library using FFI.

local ffi = require('ffi')
local bit = require('bit')
local math = require('math')
local utils = require('dns.utils')
local n16, n32 = utils.n16, utils.n32
local knot = utils.knot

-- Basic types
local void_p = ffi.typeof('void *')
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
local knot_dname_p = ffi.typeof('knot_dname_t *')
ffi.metatype( knot_dname_t, {
	__new = function (ct, name, len)
		assert(name ~= nil)
		len = len or #name
		local dname = ffi.new(ct, len + 1)
		-- Check input wire format, malformed names must not be passed through this point
		if knot.knot_dname_unpack(dname.bytes, ffi.cast(knot_dname_p, name), len + 1, nil) <= 0 then
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
			knot.knot_dname_to_lower(copy)
			return copy
		end,
		len = function(dname)
			assert(ffi.istype(knot_dname_t, dname))
			return (utils.dnamelen(dname))
		end,
		labels = function(dname)
			assert(ffi.istype(knot_dname_t, dname))
			return (knot.knot_dname_labels(dname, nil))
		end,
		within = function(dname, parent)
			assert(ffi.istype(knot_dname_t, dname))
			assert(parent ~= nil)
			if type(parent) == 'string' then parent = knot_dname_t(parent) end
			return (knot.knot_dname_in(parent, dname) == true)
		end,
		wildcard = function(dname)
			assert(ffi.istype(knot_dname_t, dname))
			return dname.bytes[0] == 1 and dname.bytes[1] == 42 -- '\1*'
		end,
		parentof = function(dname, child)
			assert(ffi.istype(knot_dname_t, child))
			assert(child ~= nil)
			return child:within(dname)
		end,
		towire = function(dname, len)
			assert(ffi.istype(knot_dname_t, dname))
			return (ffi.string(dname.bytes, len or dname:len()))
		end,
		tostring = function(dname)
			assert(ffi.istype(knot_dname_t, dname))
			return (ffi.string(knot.knot_dname_to_str(dname_buf, dname, 255)))
		end,
		split = function(dname)
			assert(ffi.istype(knot_dname_t, dname))
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
		return knot_dname_t(rdata, utils.dnamelen(rdata))
	end,
	soa_mailbox = function(rdata)
		rdata = rdata + utils.dnamelen(rdata) -- Primary NS
		return knot_dname_t(rdata, utils.dnamelen(rdata))
	end,
	soa_serial = function(rdata)
		rdata = rdata + utils.dnamelen(rdata) -- Primary NS
		rdata = rdata + utils.dnamelen(rdata) -- Mailbox
		return n32(ffi.cast(u32_p, rdata)[0])
	end,
	soa_minttl = function(rdata)
		rdata = rdata + utils.dnamelen(rdata) -- Primary NS
		rdata = rdata + utils.dnamelen(rdata) -- Mailbox
		rdata = rdata + 4 * ffi.sizeof('uint32_t')
		return n32(ffi.cast(u32_p, rdata)[0])
	end,
	len = utils.rdlen,
	data = utils.rddata,
}

-- Metatype for RR set
local rrset_buflen = (64 + 1) * 1024
local rrset_buf = ffi.new('char [?]', rrset_buflen)
local knot_rrset_t = ffi.typeof('knot_rrset_t')
ffi.metatype( knot_rrset_t, {
	__gc = function (rr)
		if rr._owner ~= nil then ffi.C.free(rr._owner) end
		if rr.rrs.count > 0 then ffi.C.free(rr.rrs.rdata) end
	end,
	__new = function (ct, owner, rrtype, rrclass, _)
		local rr = ffi.new(ct)
		rr._owner = owner and knot.knot_dname_copy(owner, nil)
		rr._type = rrtype or 0
		rr.rclass = rrclass or const_class.IN
		rr.additional = nil
		return rr
	end,
	__lt = function (a, b) return a:lt(a, b) end,
	__tostring = function(rr) return rr:tostring() end,
	__ipairs = function (self) return utils.rdataiter, self, {-1, self.rrs.rdata} end,
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
		owner = function(rr) return rr._owner[0] end,
		type = function(rr) return rr._type end,
		class = function(rr) return rr.rclass end,
		ttl = function(rr, ttl)
			assert(ffi.istype(knot_rrset_t, rr))
			if ttl ~= nil then rr._ttl = ttl end
			return rr._ttl
		end,
		rdata = function(rr, i)
			assert(ffi.istype(knot_rrset_t, rr))
			local data = utils.rdsetget(rr, i)
			return ffi.string(utils.rddata(data), utils.rdlen(data))
		end,
		count = function (rr)
			return tonumber(rr.rrs.count)
		end,
		empty = function (rr)
			return rr.rrs.count == 0
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
			rr._type = rrtype or 0
			rr.rclass = rrclass or const_class.IN
			-- @note RR set structure is managed by LuaJIT allocator, the owner and contents is
			--       managed on the C side as GC is unaware of assignments in struct fields
			if rr._owner ~= nil then
				ffi.C.free(rr._owner)
				rr._owner = nil
			end
			if owner then
				rr._owner = knot.knot_dname_copy(owner, nil)
			end
			rr.rrs.count = 0
			rr.rrs.rdata = nil
			rr.additional = nil
			return rr
		end,
		add = function(rr, data, ttl, rdlen)
			assert(ffi.istype(knot_rrset_t, rr))
			ttl = ttl or rr:ttl()
			rdlen = rdlen or #data
			return (knot.knot_rrset_add_rdata(rr, data, rdlen, ttl, nil) == 0 and rr)
		end,
		copy = function (rr, dst)
			assert(ffi.istype(knot_rrset_t, rr))
			if dst then
				assert(ffi.istype(knot_rrset_t, rr))
				dst:init(rr:owner(), rr:type(), rr:class())
			else
				dst = knot_rrset_t(rr:owner(), rr:type(), rr:class())
			end
			if rr.rrs.count > 0 then
				dst.rrs.count = rr.rrs.count
				local rdlen = utils.rdsetlen(rr)
				dst.rrs.rdata = ffi.C.calloc(1, rdlen)
				ffi.copy(dst.rrs.rdata, rr.rrs.rdata, rdlen)
			end
			return dst
		end,
		merge = function (rr, next)
			assert(ffi.istype(knot_rrset_t, rr))
			assert(ffi.istype(knot_rrset_t, next))
			for _, data in ipairs(next) do
				assert(rr:add(utils.rddata(data), rr:ttl(), utils.rdlen(data)))
			end
		end,
		clear = function (rr)
			assert(ffi.istype(knot_rrset_t, rr))
			if rr.rrs.count > 0 then
				ffi.C.free(rr.rrs.rdata)
				rr.rrs.count = 0
				rr.rrs.rdata = nil
			end
		end,
		tostring = function(rr, i)
			assert(ffi.istype(knot_rrset_t, rr))
			if rr:count() > 0 then
				local ret
				if i then
					ret = knot.knot_rrset_txt_dump_data(rr, i, rrset_buf, rrset_buflen, knot.KNOT_DUMP_STYLE_DEFAULT)
				else
					if rr._owner == nil then return end -- Uninitialised RR set
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
	if val ~= nil then rr.rclass = val end
	return rr:class()
end
local function edns_do(rr, val)
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
	if pkt.opt_rr ~= nil then
		local opt = pkt.opt_rr
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
	if pkt.tsig_rr ~= nil then
		data = data..string.format(';; TSIG PSEUDOSECTION:\n%s', pkt.tsig_rr:tostring())
	end
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
local function pkt_free(pkt)
	pkt_unref(pkt)
	knot.knot_pkt_free(pkt)
end
ffi.metatype( knot_pkt_t, {
	__new = function (_, size, wire)
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
					assert(pkt.opt_rr ~= nil, 'cannot use extended without OPT in packet')
					local upper = bit.rshift(val, 4)
					knot.knot_edns_set_ext_rcode(pkt.opt_rr, upper)
				end
				pkt.wire[3] = bit.bor(bit.band(pkt.wire[3], 0xf0), val)
			end
			local ret = bit.band(pkt.wire[3], 0x0f)
			-- Add extended RCODE if OPT is present
			if pkt.opt_rr ~= nil then
				ret = bit.bor(ret, bit.lshift(knot.knot_edns_get_ext_rcode(pkt.opt_rr), 4))
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
		qclass = function(pkt)
			if pkt == nil or pkt.qname_size == 0 then
				return nil
			end

			return pkt_cnt(pkt, 12 + pkt.qname_size + ffi.sizeof('uint16_t'))
		end,
		qtype  = function(pkt)
			if pkt == nil or pkt.qname_size == 0 then
				return nil
			end

			return pkt_cnt(pkt, 12 + pkt.qname_size)
		end,
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
				if rrset:type() == const_type.OPT then pkt.opt_rr = rrset end
			end
			local ret = knot.knot_pkt_put_rotate(pkt, compr or 0, rrset, 0, 0)
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
				if pkt.tsig_rr ~= nil then pkt:arcount(pkt:arcount() + 1) end
				-- Strip EDNS from wire if asked to
				if pkt.opt_rr ~= nil and strip_edns then
					local opt_len = knot.knot_edns_wire_size(pkt.opt_rr)
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
	-- Metatypes
	todname = function (udata) return ffi.cast(knot_dname_p, udata) end,
	tordata = function (udata) return ffi.cast('knot_rdata_t *', udata) end,
	torrset = function (udata) return ffi.cast('knot_rrset_t *', udata) end,
	topacket = function (udata) return ffi.cast('knot_pkt_t *', udata) end,
	-- Utils
	strerr = strerr,
	hexdump = utils.hexdump,
	utils = utils,
}

return M
