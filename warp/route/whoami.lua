local dns = require('dns')

local M = {}

-- ECS constants
local ecs_family = {
	inet = 1,
	inet6 = 2
}

-- Parse ECS subnet
local function parse_ecs(data)
	if not data then
		return nil, 'no ecs present'
	end
	-- Read the ECS header
	local w = dns.utils.wire_reader(data, #data)
	local family = w:u16()
	local source = w:u8()
	local scope = w:u8()
	-- Pad to the last byte
	local blen = source
	if blen % 8 ~= 0 then
		blen = blen + (8 - (blen % 8))
	end
	-- Read prefix and pad to full address size
	local addr = w:bytes(blen / 8)
	if family == ecs_family.inet then
		addr = addr .. string.rep('\0', (32 - blen) / 8)
	elseif family == ecs_family.inet6 then
		addr = addr .. string.rep('\0', (128 - blen) / 8)
	else
		return nil, 'unknown address type'
	end
	return tostring(dns.utils.inaddr(addr, 0).addr), source, scope
end

-- Sign records in the answer
local function serve(self, req, writer)
	if req.answer:aa() or req.qtype ~= dns.type.TXT then return end
	-- Act only within zone and for non-meta types
	local qname, apex = req.qname, self.soa:owner()
	if not qname:within(apex) then return end
	req.soa = self.soa
	-- TXT whoami.<zone>, synthesise TXT
	if qname:equals(self.whoami) then
		local addr = req.addr
		if type(addr) ~= 'string' then addr = tostring(addr.addr) end
		local rr = dns.rrset(qname, dns.type.TXT)
		           :add(dns.rdata.txt(addr))
		req.answer:put(rr, true)
		req.answer:aa(true)
		req.nocache = true
	-- TXT clock.<zone>, synthesise TXT
	elseif qname:equals(self.clock) then
		local rr = dns.rrset(qname, dns.type.TXT)
		           :add(dns.rdata.txt(string.format('%d', os.time())))
		req.answer:put(rr, true)
		-- Synthesise TZ offset
		rr = dns.rrset(qname, dns.type.TXT)
			 :add(dns.rdata.txt(string.format('%s', os.date("%z"))))
		req.answer:put(rr, true)
		req.answer:aa(true)
		req.nocache = true
	-- TXT ecs.<zone>, synthesise TXT
	elseif qname:equals(self.ecs) then
		local addr, source = parse_ecs(dns.edns.option(req.query.opt, dns.option.SUBNET))
		if addr then
			local rr = dns.rrset(qname, dns.type.TXT)
			           :add(dns.rdata.txt(string.format('%s/%d', addr, source)))
			req.answer:put(rr, true)
		else
			table.insert(req.authority, req.soa)
		end
		req.answer:aa(true)
		req.nocache = true
	end
end

function M.init(conf)
	conf = conf or {}
	conf.zone = conf.zone or 'example'
	conf.whoami = dns.dname.parse(string.format('whoami.%s', conf.zone))
	conf.clock = dns.dname.parse(string.format('clock.%s', conf.zone))
	conf.ecs = dns.dname.parse(string.format('ecs.%s', conf.zone))
	-- Create SOA for this zone
	local apex = assert(dns.dname.parse(conf.zone), 'invalid zone: '..conf.zone)
	local soa = 'ns.dns.%s hostmaster.%s %d 28800 7200 604800 5'
	conf.soa = dns.rrset(apex, dns.type.SOA)
	           :add(dns.rdata.soa(soa:format(conf.zone, conf.zone, os.time())), 5)
	conf.serve = serve
	return conf
	
end

return M