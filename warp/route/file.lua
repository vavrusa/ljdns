local dns, rrparser = require('dns'), require('dns.rrparser')
local ffi = require('ffi')

local M = {}

-- Add RR to packet and send it out if it's full
local function add_rr(req, writer, rr, xfer)
	if not req.answer:put(rr, xfer) then
		assert(writer(req, req.answer, req.addr))
		req.msg:toanswer(req.answer)
		req.answer:aa(true)
		req.answer:put(rr, xfer) -- Promise not to access RR afterwards
		return 1
	end
	return 0
end
-- Find appropriate zonefile and mtime for this query
local function zone_get(self, name)
	-- Check if limited to a single zone
	if self.zone then
		if not name:within(self.zone) then
			return name:tostring(), 0
		end
		return self.path, 1
	end
	-- Find zone file in given directory
	local zonefile = name:tostring() .. 'zone'
	if zonefile:find('/', 1, true) then
		zonefile = zonefile:gsub('/','_')
	else
		assert(not zonefile:find('..', 1, true), 'QNAME contains "..", this is considered malformed')
	end
	local mtime = dns.utils.mtime(self.path .. zonefile)
	for _ = 2, name:labels() do
		if mtime > 0 then break end
		local next_label = zonefile:find('.', 1, true)
		zonefile = zonefile:sub(next_label + 1)
		mtime = dns.utils.mtime(self.path .. zonefile)
	end
	return self.path .. zonefile, mtime
end

-- Answer query from zonefile
local function serve(self, req, writer)
	-- Check if already answered
	if req.answer:aa() then return end
	local name = req.qname
	local zonefile, mtime = zone_get(self, name)
	if mtime == 0 then
		req:vlog('%s: refused (no zone found)', zonefile)
		req.answer:rcode(dns.rcode.REFUSED)
		return -- No file to process, bail
	end

	-- Note: rrset is going to contain unsafe owner to avoid allocation on every RR (expensive)
	--       we use custom GC routine to not attempt to free unsafe owner
	req.file_path = zonefile
	req.file_mtime = mtime
	req.file_parser = req.file_parser or assert(rrparser.new())
	req.file_rr = req.file_rr or ffi.gc(dns.rrset(nil, 0), dns.rrset.clear)

	-- Check for zone transfers
	local xfer = (req.qtype == dns.type.AXFR or req.qtype == dns.type.IXFR)
	if xfer and not req.is_tcp then
		req:vlog('zone transfer over udp, rejected')
		req.answer:tc(true)
		return false
	end

	-- Start streaming zone
	req.answer:aa(true)
	req.answer:rcode(dns.rcode.NXDOMAIN)
	local found, soa, nrrs, npkts = false, nil, 0, 0
	local parser, rr = req.file_parser, req.file_rr
	rr.raw_owner = dns.todname(parser.r_owner)
	req:vlog('%s: stream start (mtime %d)', req.file_path, req.file_mtime)
	assert(parser:open(req.file_path))
	while parser:parse() do
		rr.raw_type = parser.r_type
		-- Allow breaking search early for non-transfers
		local skip = false
		if not xfer then
			-- Zone file is sorted, we either find an exact match
			-- or we can abort the search if we're past it
			local cmp = name:compare(rr:owner())
			if cmp < 0 then break -- Past QNAME, this name will not exist
			elseif cmp > 0 or req.qtype ~= rr:type() then
				skip = true       -- Skip this record
			else found = true end -- Remember when we find a result
			-- Matching name found, turn into NOERROR
			if cmp == 0 then req.answer:rcode(dns.rcode.NOERROR) end
		end
		-- Construct RR set object and append to packet
		if not skip then
			-- Zone transfers are optimised and stream records to message stream
			-- without keeping them around for further manipulation
			if xfer then
				rr:add(parser.r_data, parser.r_ttl, parser.r_data_length)
				npkts = npkts + add_rr(req, writer, rr, xfer)
			else
				local copy = rr:copy()
				copy:add(parser.r_data, parser.r_ttl, parser.r_data_length)
				npkts = npkts + add_rr(req, writer, copy, xfer)
			end
			nrrs = nrrs + 1
			rr:clear()
		end
		-- Keep SOA handy for later
		if not soa and rr:type() == dns.type.SOA then
			soa = rr:copy()
			soa:add(parser.r_data, parser.r_ttl, parser.r_data_length)
			req:vlog('%s: found soa %s', req.file_path, soa:tostring(0))
		end
	end
	parser:reset()

	-- Add final SOA or SOA non-existence proof
	if soa then
		if xfer then
			add_rr(req, writer, soa, xfer)
		elseif not found then
			table.insert(req.authority, soa) -- Authority SOA
		end
		req.soa = soa
	end
	req:vlog('%s: stream end (%d records, %d messages)', req.file_path, nrrs, npkts)
	return not xfer, nil
end

-- Module initialiser
function M.init(conf)
	conf = conf or {}
	conf.path = conf.path or '.'
	-- Check if given path is file or directory
	if not dns.utils.isdir(conf.path) then
		conf.zone = conf.zone or conf.path:match '.+/(%w+)'
		conf.zone = dns.dname.parse(conf.zone)
		assert(conf.zone, string.format('file "%s" has unknown zone, provide file.zone = <name>', conf.path))
	else
		conf.path = conf.path .. '/'
	end
	conf.serve = serve
	return conf
end

return M