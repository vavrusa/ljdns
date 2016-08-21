local dns, go, rrparser = require('dns'), require('dns.aio'), require('dns.rrparser')
local ffi = require('ffi')

local M = {}

-- Add RR to packet and send it out if it's full
local function add_rr(req, writer, rr)
	if not req.answer:put(rr, true) then
		assert(writer(req, req.answer, req.addr))
		req.msg:toanswer(req.answer)
		req.answer:aa(true)
		req.answer:put(rr, true) -- Promise not to access RR afterwards
		return 1
	end
	return 0
end
-- Find appropriate zonefile and mtime for this query
local function zone_get(name)
	local zonefile = name:tostring()..'zone'
	assert(not zonefile:find('/', 1, true) and not zonefile:find('..', 1, true))
	local mtime = dns.utils.mtime(zonefile)
	for _ = 2, name:labels() do
		if mtime > 0 then break end
		local next_label = zonefile:find('.', 1, true)
		zonefile = zonefile:sub(next_label + 1)
		mtime = dns.utils.mtime(zonefile)
	end
	return zonefile, mtime
end

-- Check if we have a valid zonefile
local function accept(self, req)
	local name = req.query:qname()
	local zonefile, mtime = zone_get(name)
	if mtime == 0 then
		req:vlog('%s: refused (no zone found)', name)
		req.answer:rcode(dns.rcode.REFUSED)
		return false
	else
		req.file_path = zonefile
		req.file_mtime = mtime
		return true
	end
end

-- Answer query from zonefile
local function serve(self, req, writer)
	local tstart = go.now()
	local name = req.query:qname()
	-- Note: rrset is going to contain unsafe owner to avoid allocation on every RR (expensive)
	--       we use custom GC routine to not attempt to free unsafe owner
	if not req.file_parser then req.file_parser = assert(rrparser.new()) end
	if not req.rr then req.file_rr = ffi.gc(dns.rrset(nil, 0), dns.rrset.clear) end
	req.answer:aa(true)
	req.answer:rd(false)
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
		end
		-- Construct RR set object and append to packet
		if not skip then
			rr:add(parser.r_data, parser.r_ttl, parser.r_data_length)
			nrrs = nrrs + 1
			npkts = npkts + add_rr(req, writer, rr)
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
		if not found and not req.xfer then
			req.answer:begin(dns.section.AUTHORITY)
		end
		if not found or req.xfer then
			add_rr(req, writer, soa)
		end
	end
	req:vlog('%s: stream end (%d records, %d messages, %d msec)',
	     req.file_path, nrrs, npkts, (go.now() - tstart) * 1000.0)
	return true, nil
end

-- Export module API
M.accept = accept
M.serve = serve
return M