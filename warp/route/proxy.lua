local dns, nbio = require('dns'), require('dns.nbio')

local M = {max_pool = 256}

-- Protocol transports
local proto = { tcp = 1, udp = 2, unix = 3, }
-- Tracking timestamp
local track_ts, expire_ts = 1, 1
-- Rate limit tracking
local rate = 0
-- Origin selection algorithm
local method = {
	-- Round robin selection
	roundrobin = function(self, req)
		return -- Default
	end,
	-- Weighted round robin selection
	weighted = function(self, req)
		local x, cm = math.random(1, self.sum_weight), 0
		for i = 1, #self.origins do
			local o = self.origins[i]
			if x > cm and x <= cm + o.weight then
				return o
			end
			cm = cm + o.weight
		end
	end,
	-- Shortest distance selection
	shortest = function(self, req)
		-- Reset polls
		if not track_ts or track_ts < req.now then
			for _,o in ipairs(self.origins) do o.rtt = 1 end
			track_ts = req.now + 30
		end
		-- Select minimum distance
		local min, min_o = 0
		for i = 1, #self.origins do
			local o = self.origins[i]
			if o.rtt < min then min, min_o = o.rtt, o end
		end
		return min_o
	end,
	-- Probabilistic distance tracking selection
	track = function(self, req)
		-- Count relative total distance
		local sum = 0
		for i = 1, #self.origins do
			sum = sum + (self.max_rtt - self.origins[i].rtt)
		end
		-- Dice roll and select distance
		local x, cm = math.random(1, sum), 0
		for i = 1, #self.origins do
			local o = self.origins[i]
			local inc = cm + (self.max_rtt - o.rtt)
			if x > cm and x <= inc then
				return o
			end
			cm = inc
		end
	end,
}
M.method = method

-- Pool connections
local pools = {}

local function getsocket(self, req, endpoint, fixed)
	local pool = endpoint.pool
	-- Fetch a valid pooled connection
	local c, id
	if fixed then
		id = req.query:id() % self.poolsize + 1
		c = pool[id]
	else
		c = table.remove(pool)
	end
	if c then
		req:vlog('reused pooled connection')
		return c, true, id
	end
	-- Create socket and connect it to endpoint
	local stream = (self.proto == proto.tcp)
	local c, err = nbio.socket(endpoint.family, stream, true)
	if not c then return nil, err end
	local ok, err = nbio.connect(c, endpoint.host, endpoint.port, stream)
	if not ok then c:close() return nil, err end
	-- Save connection in fixed slot
	if fixed and not pool[id] then
		pool[id] = c
	end
	return c, nil, id
end

local function sendrecv(self, sock, req)
	if self.proto == proto.tcp then
		return nbio.tcpxchg(sock, req.query, req.answer)
	elseif self.proto == proto.udp then
		local ok, err = nbio.udpsend(sock, req.query.wire, req.query.size)
		if not ok then
			return nil, err
		end
		return nbio.udprecv(sock, req.answer.wire, req.answer.max_size)
	else
		return nil, 'unknown protocol'
	end
end

local function rescan(req, pkt, bytes)
	pkt.parsed = 0
	pkt.size = bytes
	-- Scan question
	local ok, err = pkt:parse_question()
	if not ok then return ok, err end
	-- Parse answer and remember wire position
	ok, err = pkt:parse_section(dns.section.ANSWER)
	if not ok then return ok, err end
	local pos = pkt.parsed
	-- Parse authority and additional and add to tables
	-- It is done in order to be able to modify or expand the records
	for s = dns.section.AUTHORITY, dns.section.ADDITIONAL do
		ok, err = pkt:parse_section(s)
		if not ok then return ok, err end
		local dst = (s == dns.section.AUTHORITY) and req.authority or req.additional
		for _, rr in ipairs(pkt:section(s)) do
			if not dns.type.ismeta(rr:type()) then
				table.insert(dst, rr)
				-- Remember SOA to establish authority
				if rr:type() == dns.type.SOA then
					req.soa = rr
				end
			end
		end
	end
	-- Rewind to answer section
	pkt.parsed, pkt.size = pos, pos
	pkt.cur_section = dns.section.ANSWER
	pkt:nscount(0)
	pkt:arcount(0)
	return true
end

local function serve(self, req)
	-- Do not proxy transfers
	if req.xfer then return end
	-- Choose transport protocol and origin
	local dst = self:select(req)
	if not dst then
		dst = self.origins[math.random(1, #self.origins)]
	end
	-- Clear answer
	req.answer:clear()
	table.clear(req.authority)
	table.clear(req.additional)
	-- Check rate limit
	if self.rate then
		if expire_ts < req.now then
			rate, expire_ts = self.rate, req.now + 1
		else
			if rate == 0 then
				req.query:toanswer(req.answer)
				req.answer:rcode(dns.rcode.SERVFAIL)
				return false
			end
			rate = rate - 1
		end
	end
	-- Establish connection
	local now, bytes, err = nbio.now(), 0
	for _ = 1, 3 do
		req:vlog('forwarding to host: %s, port: %d', dst.host, dst.port)
		local c, reused, id = getsocket(self, req, dst, true)
		if not c then
			req:vlog('connection failed: %s', reused)
		else
			bytes, err = sendrecv(self, c, req)
			if not bytes or bytes == 0 then
				req:vlog('sendrecv failed: %s', err)
				if not reused then error(err) end
				c:close() -- Disconnected, close and retry
				dst.pool[id] = nil
			else
				break
			end
		end
	end
	-- Reparse answer
	local ok, err = rescan(req, req.answer, bytes)
	if not ok then
		req:vlog('bad response: %s', err)
		req.query:toanswer(req.answer)
		req.answer:rcode(dns.rcode.SERVFAIL)
		return false
	end
	-- Update statistics
	local rtt = 1000 * (nbio.now() - now)
	req:vlog('answer rcode: %s, rtt: %dms', dns.tostring.rcode[req.answer:rcode()], rtt)
	dst.rtt = (dst.rtt + rtt) / 2
end

function M.init(conf)
	conf = conf or {}
	conf.proto = conf.proto or 'udp'
	conf.weights = conf.weights or {}
	conf.select = method[conf.select] or method.roundrobin
	conf.poolsize = conf.poolsize or M.max_pool
	assert(proto[conf.proto], 'proxy.proto is invalid, expected (udp,tcp,unix)')
	conf.proto = proto[conf.proto]
	assert(conf.origins, 'proxy.origins are not configured')
	assert(type(conf.origin) ~= 'table' or #conf.origins == 0,
	       'proxy.origins are empty, expected non-empty table')
	-- Parse origins
	local origins, sum = {}, 0
	for i,v in ipairs(conf.origins) do
		local host, port = dns.utils.addrparse(v)
		local weight = (conf.weights[i] or 100) / #conf.origins
		if not pools[v] then pools[v] = {} end
		local o = {pool=pools[v], host=host, port=port, family=nbio.family(host), weight=weight, rtt=1}
		table.insert(origins, o)
		sum = sum + weight
	end
	conf.max_rtt = 1
	conf.sum_weight = sum
	conf.serve = serve
	conf.origins = origins
	return conf
end

return M