local ffi, dns, utils = require('ffi'), require('dns'), require('dns.utils')
local json = require('cjson')
local http = require('resty.http')
local getaddr, af = require('dns.nbio').addr, require('syscall').c.AF

local M = {}

local function key(qname)
	local key = qname:split()
	utils.reverse(key)
	return table.concat(key, '/')
end

local function getname(k, strip)
	local labels = {}
	for l in k:gmatch '[^/]+' do
		table.insert(labels, l)
	end
	if strip then
		for _ = 1, strip do table.remove(labels) end
	end
	utils.reverse(labels)
	return dns.dname.parse(table.concat(labels, '.'))
end

local function getnode(n, count, key)
	n = json.decode(n)
	n.ttl = n.ttl or 3600
	n.port = n.port or 0
	n.priority = n.priority or 10
	n.weight = (n.weight or 100) / count
	n.key = key
	return n
end

local function unpackdir(t, dir)
	for _,n in ipairs(dir) do
		if n.value then
			table.insert(t, n)
		else
			unpackdir(t, n.nodes)
		end
	end
end

local function addrecords(self, req, name, entry, writer)
	if not writer then return true end
	entry = json.decode(entry).node
	local plen = #self.conf.prefix + 1
	-- Unpack single node
	if entry.value then
		local rr = writer(req, name, getnode(entry.value, 1, entry.key:sub(plen)), self)
		if rr then req.answer:put(rr) end
	elseif entry.dir then
		-- Unpack directory and linearise
		local nodes = {}
		unpackdir(nodes, entry.nodes)
		local count = #nodes
		for _,n in ipairs(nodes) do
			local rr = writer(req, name, getnode(n.value, count, n.key:sub(plen)), self)
			if rr == false then break end
			if rr then req.answer:put(rr) end
		end
	end
	return true
end

local function addextra(req, v)
	local host = v.host
	local ok, addr = pcall(getaddr, host, 0)
	if ok then
		-- Add additional records for address records in host
		host = getname(v.key, v.targetstrip)
		local rr = dns.rrset(host, addr.family == af.INET and dns.type.A or dns.type.AAAA)
		rr:add(ffi.cast('char *', addr.addr), v.ttl, ffi.sizeof(addr.addr))
		table.insert(req.additional, rr)
	else
		host = dns.dname.parse(host)
	end
	return host
end

local function gethost(req, k, v, family, rrtype, self)
	-- Convert to address
	local ok, addr = pcall(getaddr, v.host, v.port)
	if not ok then
		-- Do not add CNAME if there is already answer
		if not req.answer:empty() then
			return
		end
		local target = dns.dname.parse(v.host)
		local rr = dns.rrset(k, dns.type.CNAME)
		rr:add(target.bytes, v.ttl, target:len())
		req.answer:put(rr)
		if not self.zone or target:within(self.zone) then
			M.answer(self, req, http.new(), target, rrtype)
			return
		end
		-- NYI: Follow and flatten CNAMEs
		req:log('warn', 'NYI: external resolution: ' .. v.host)
		return false -- No other records if CNAME is inserted
	end
	-- Accept only specific family
	if addr.family ~= family then return end
	-- Append to response
	local rr = dns.rrset(k, rrtype)
	rr:add(ffi.cast('char *', addr.addr), v.ttl, ffi.sizeof(addr.addr))
	return rr
end

local function getsoa(req, zone, ttl)
	local rr = dns.rrset(zone, dns.type.SOA)
	local soa = 'ns.dns.%s hostmaster.%s %d 28800 7200 604800 60'
	rr:add(dns.rdata.soa(soa:format(zone, zone, req.now)), ttl or 60)
	req.soa = rr
	return rr
end

-- Supported records generators
local generators = {
	[dns.type.SRV] = function (req, k, v)
		local host = addextra(req, v)
		local srv = dns.rdata.srv(v.priority, v.weight, v.port, host)
		local rr = dns.rrset(k, dns.type.SRV)
		rr:add(srv, v.ttl, ffi.sizeof(srv))
		return rr
	end,
	[dns.type.A] = function (req, k, v, self)
		return gethost(req, k, v, af.INET, dns.type.A, self)
	end,
	[dns.type.AAAA] = function (req, k, v, self)
		return gethost(req, k, v, af.INET6, dns.type.AAAA, self)
	end,
	[dns.type.NS] = function (req, k, v)
		addextra(req, v)
		local rr = dns.rrset(k, dns.type.NS)
		rr:add(k.bytes, v.ttl, k:len())
		return rr
	end,
	[dns.type.MX] = function (req, k, v)
		if not v.mail then return end
		local host = addextra(req, v)
		local rr = dns.rrset(k, dns.type.MX)
		local mx = dns.rdata.mx(v.priority, host)
		rr:add(mx, v.ttl, ffi.sizeof(mx))
		return rr
	end,
	[dns.type.PTR] = function (req, k, v)
		local rr = dns.rrset(k, dns.type.PTR)
		local target = dns.dname.parse(v.host)
		rr:add(target.bytes, v.ttl, target:len())
		return rr
	end,
}

local function answer(self, req, c, name, rrtype)
	-- SOA query is synthesised
	if rrtype == dns.type.SOA then
		local soa = getsoa(req, self.zone)
		if name:equals(self.zone) then
			req.answer:put(soa)
		else
			table.insert(req.authority, soa)
		end
		return true
	end
	-- Convert QNAME to query key
	local k = key(name)
	-- NS records have special namespace
	if rrtype == dns.type.NS then k = k .. '/dns/ns' end
	local ok, err = c:connect(self.conf.host, self.conf.port)
	if not ok then error(err) end
	local res, err = c:request {
		path = self.conf.url:format(k),
	}
	-- Check response and serve
	if err or res.status ~= 200 or not res.has_body then
		res = res or {status=500, reason=err}
		req.answer:rcode(dns.rcode.SERVFAIL)
		req:vlog('etcd url: %s code: %d reason: %s', self.conf.url .. k, res.status, res.reason)
		return nil, err
	end
	local body = res:read_body()
	-- Generate CoreDNS response
	return addrecords(self, req, name, body, generators[rrtype])
end
M.answer = answer

local function serve(self, req)
	if req.nocache or req.xfer or req.answer:aa() then return end
	local qname, qtype = req.query:qname(), req.query:qtype()
	if self.zone and not qname:within(self.zone) then return end
	-- Answer type
	local ok, err = answer(self, req, http.new(), qname, qtype)
	if not ok then
		req:log('error', 'etcd: %s', err)
	else
		req.answer:aa(true)
		if not req.soa then getsoa(req, self.zone) end
	end
end

function M.init(conf)
	conf = conf or {}
	conf.schema = conf.schema or 'http'
	conf.prefix = conf.prefix or '/skydns'
	conf.host = conf.host or '127.0.0.1'
	conf.port = conf.port or 2379
	conf.timeout = conf.timeout or 100
	conf.url = '/v2/keys' .. conf.prefix .. '/%s?recursive=true'
	if conf.host:find '/' then
		conf.port = nil
	end

	return {zone=dns.dname.parse(conf.zone), conf=conf, serve=serve}
end

return M