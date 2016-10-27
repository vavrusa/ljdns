local dns = require('dns')

local M = {}

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
		req.answer:aa(true)
		req.nocache = true
	end
end

function M.init(conf)
	conf = conf or {}
	conf.zone = conf.zone or 'example'
	conf.whoami = dns.dname.parse(string.format('whoami.%s', conf.zone))
	conf.clock = dns.dname.parse(string.format('clock.%s', conf.zone))
	-- Create SOA for this zone
	local apex = assert(dns.dname.parse(conf.zone), 'invalid zone: '..conf.zone)
	local soa = 'ns.dns.%s hostmaster.%s %d 28800 7200 604800 5'
	conf.soa = dns.rrset(apex, dns.type.SOA)
	           :add(dns.rdata.soa(soa:format(conf.zone, conf.zone, os.time())), 5)
	conf.serve = serve
	return conf
	
end

return M