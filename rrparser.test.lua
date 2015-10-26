local zonefile = require('rrparser')
local fname = 'examples/example.com.zone'

-- Parse zone file to table
local parsed_data = zonefile.parse_file(fname)
assert(parsed_data ~= nil)
assert(#parsed_data == 10)

-- Parse file lines
local rc = 0
local parser = zonefile.parser()
for line in io.lines(fname) do
	rc = parser:read(line .. '\n')
	assert(rc == 0)
	assert(parser.error_code == 0)
end

-- Parse record (custom callbacks)
parser = zonefile.parser(function (parser)
	local rr = parser:current_rr()
	assert(rr.class == 1)
	assert(rr.ttl == 3600)
	assert(rr.owner == '\3foo\0')
	assert(rr.rdata == '\3bar\0')
end)
rc = parser:read("foo. IN 3600 NS bar.\n")
assert(rc == 0)
assert(parser.error_code == 0)
print('rrparser ok')
