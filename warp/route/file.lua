local dns, rrparser = require('dns'), require('dns.rrparser')
local ffi = require('ffi')

local M = {}

-- Module initialiser
function M.init(conf)
	return M -- No init
end

-- Add RR to packet and send it out if it's full
local function add_rr(req, writer, rr)
	if not req.answer:put(rr, req.xfer) then
		assert(writer(req, req.answer, req.addr))
		req.msg:toanswer(req.answer)
		req.answer:aa(true)
		req.answer:put(rr, req.xfer) -- Promise not to access RR afterwards
		return 1
	end
	return 0
end
-- Find appropriate zonefile and mtime for this query
local function zone_get(name)
	local zonefile = name:tostring()..'zone'
	if zonefile:find('/', 1, true) then
		zonefile = zonefile:gsub('/','_')
	else
		assert(not zonefile:find('..', 1, true), 'QNAME contains "..", this is considered malformed')
	end
	local mtime = dns.utils.mtime(zonefile)
	for _ = 2, name:labels() do
		if mtime > 0 then break end
		local next_label = zonefile:find('.', 1, true)
		zonefile = zonefile:sub(next_label + 1)
		mtime = dns.utils.mtime(zonefile)
	end
	return zonefile, mtime
end

-- Answer query from zonefile
local function serve(self, req, writer)
	-- Check if already answered
	if req.answer:aa() then return end
	local name = req.query:qname()
	local zonefile, mtime = zone_get(name)
	if mtime == 0 then
		req:vlog('%s: refused (no zone found)', zonefile)
		req.answer:rcode(dns.rcode.REFUSED)
		return -- No file to process, bail
	end
	req.file_path = zonefile
	req.file_mtime = mtime
	local name = req.query:qname()
	-- Note: rrset is going to contain unsafe owner to avoid allocation on every RR (expensive)
	--       we use custom GC routine to not attempt to free unsafe owner
	if not req.file_parser then req.file_parser = assert(rrparser.new()) end
	if not req.rr then req.file_rr = ffi.gc(dns.rrset(nil, 0), dns.rrset.clear) end
	req.answer:aa(true)
	req.answer:rd(false)
	req.answer:rcode(dns.rcode.NXDOMAIN)
	-- Start streaming zone
	local parser, rr = req.file_parser, req.file_rr
	rr.raw_owner = dns.todname(parser.r_owner)
	local found, soa, nrrs, npkts, qtype = false, nil, 0, 0, req.query:qtype()
	req:vlog('%s: stream start (mtime %d)', req.file_path, req.file_mtime)
	assert(parser:open(req.file_path))
	while parser:parse() do
		rr.raw_type = parser.r_type
		-- Allow breaking search early for non-transfers
		local skip = false
		if not req.xfer then
			-- Zone file is sorted, we either find an exact match
			-- or we can abort the search if we're past it
			local cmp = name:compare(rr:owner())
			if cmp < 0 then break -- Past QNAME, this name will not exist
			elseif cmp > 0 or qtype ~= rr:type() then
				skip = true       -- Skip this record
			else found = true end -- Remember when we find a result
			-- Matching name found, turn into NOERROR
			if cmp == 0 then req.answer:rcode(dns.rcode.NOERROR) end
		end
		-- Construct RR set object and append to packet
		if not skip then
			-- Zone transfers are optimised and stream records to message stream
			-- without keeping them around for further manipulation
			if req.xfer then
				rr:add(parser.r_data, parser.r_ttl, parser.r_data_length)
				npkts = npkts + add_rr(req, writer, rr)
			else
				local copy = rr:copy()
				copy:add(parser.r_data, parser.r_ttl, parser.r_data_length)
				npkts = npkts + add_rr(req, writer, copy)
			end
			nrrs = nrrs + 1
			rr:clear()
		end
		-- Keep SOA handy for later
		if not soa and rr:type() == dns.type.SOA then
			soa = rr:copy()
			soa:add(parser.r_data, parser.r_ttl, parser.r_data_length)
		end
	end
	parser:reset()
	-- Add final SOA or SOA non-existence proof
	if soa then
		if req.xfer then
			add_rr(req, writer, soa)
		elseif not found then
			table.insert(req.authority, soa) -- Authority SOA
		end
		req.soa = soa
	end
	req:vlog('%s: stream end (%d records, %d messages, %d msec)',
	     req.file_path, nrrs, npkts, (os.time() - req.now) * 1000.0)
	return not req.xfer, nil
end
M.serve = serve

return M