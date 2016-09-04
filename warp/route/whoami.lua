local dns = require('dns')

local M = {}

-- Sign records in the answer
local function serve(self, req, writer)
	-- Act only within zone and for non-meta types
	local qname = req.query:qname()
	if req.xfer or not qname:within(self.zone) then return end

	-- Empty zone, NXDOMAIN
	req.answer:aa(true)
	if not qname:equals(self.zone) then
		req.answer:rcode(dns.rcode.NXDOMAIN)
	-- If not TXT, respond with NODATA
	elseif req.query:qtype() ~= dns.type.TXT then
		req.answer:rcode(dns.rcode.NOERROR)
	-- TXT apex, synthesise TXT
	else
		local addr = req.addr
		if type(addr) ~= 'string' then addr = tostring(addr.addr) end
		local rr = dns.rrset(self.zone, dns.type.TXT)
		           :add(dns.rdata.txt(addr))
		req.answer:put(rr, true)
		req.nocache = true
	end
end

function M.init(conf)
	conf = conf or {}
	conf.zone = conf.zone or 'whoami'
	return {zone=dns.dname.parse(conf.zone), serve=serve}
	
end

return M