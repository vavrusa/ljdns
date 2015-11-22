local kdns = require('kdns')

-- Test constants
assert(kdns.class.IN == 1)
assert(kdns.class['IN'] == 1)
assert(kdns.tostring.class[1] == 'IN')
assert(kdns.tostring.class[666666] == nil)
assert(kdns.type.NS == 2)
assert(kdns.tostring.type[2] == 'NS')
assert(kdns.rcode.SERVFAIL == 2)
assert(kdns.tostring.rcode[2] == 'SERVFAIL')
assert(kdns.opcode.QUERY == 0)
assert(kdns.tostring.opcode[0] == 'QUERY')
print('[ OK ] kdns.constants')

-- Test domain names
local dname = kdns.dname('\7example\3com')
assert(dname ~= nil)
assert(tostring(dname) == 'example.com.')
dname = kdns.dname.parse('example.COM')
assert(dname == '\7example\3COM')
assert(dname:labels() == 2)
assert(dname:lower() == '\7example\3com')
assert(dname:within('\3com') == true)
assert(dname:within('\2cz') == false)
print('[ OK ] kdns.dname')

-- Test RDATA
assert(kdns.rdata.parse('A') == nil)
assert(kdns.rdata.parse('A asdf') == nil)
assert(kdns.rdata.parse('NS test') == '\4test\0')
local rd = kdns.rdata.a('1.2.3.4')
assert(rd == '\1\2\3\4')
assert(#rd == 4)
assert(kdns.rdata.mx('10 test') == '\0\10\4test\0')
assert(kdns.rdata.txt('abcd') == '\4abcd')
assert(kdns.rdata.parse('LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m') ~= nil)
kdns.rdata.parse('SRV 0 5 zzzz')
print('[ OK ] kdns.rdata')

-- Test RR sets
local rrset = kdns.rrset('\3com', kdns.type.NS)
collectgarbage()
assert(rrset ~= nil)
assert(rrset:owner() == '\3com')
assert(rrset:class() == kdns.class.IN)
assert(rrset:type()  == kdns.type.NS)
assert(#rrset == 0)
rrset:add(kdns.rdata.ns('test'), 3600)
assert(#rrset == 1)
assert(rrset:rdata(0) == '\4test\0')
collectgarbage()
print('[ OK ] kdns.rrset')

-- Test packet writing
local pkt = kdns.packet(512)
assert(pkt ~= nil)
assert(pkt:opcode())
assert(pkt:rd(true) == true)
assert(pkt:tc(true) == true)
assert(pkt:aa() == false)
assert(pkt:qr(false) == false)
assert(pkt:cd(true) == true)
assert(pkt:ad(true) == true)
assert(pkt:ra() == false)
assert(pkt:id(1234) == 1234)
assert(pkt:question('\4test', kdns.type.SOA))
assert(pkt:begin(kdns.section.ANSWER))
assert(pkt:put(rrset) == true)
collectgarbage() -- Must keep reference to RR
assert(pkt:begin(kdns.section.ADDITIONAL) == 0)
assert(pkt:put(kdns.rrset('\3com', kdns.type.A):add(kdns.rdata.a('1.2.3.4'), 3600)) == true)
collectgarbage() -- Must keep reference to RR
assert(pcall(function() pkt:begin(kdns.section.ANSWER) end) == false)
print(pkt)
local wire = pkt:towire()
kdns.hexdump(wire)
collectgarbage() -- Must keep reference to RR
print('[ OK ] kdns.packet.write')

-- Test packet reading
local copy = kdns.packet(#wire, wire)
assert(copy ~= nil)
assert(copy:parse() == true)
assert(copy:id() == pkt:id())
assert(copy:qname() == pkt:qname())
assert(copy:qtype() == pkt:qtype())
assert(copy:qclass() == pkt:qclass())
assert(copy:answers(pkt) == false)
assert(tostring(copy) == tostring(pkt))
copy:qr(true)
assert(copy:answers(pkt) == true)

-- Test packet copy
copy = pkt:copy()
collectgarbage() -- Must collect previous copy
assert(copy ~= pkt)
assert(tostring(copy) == tostring(pkt))
print('[ OK ] kdns.packet.read')

-- Test RR parser
local rrparser = require('kdns.rrparser')
local fname = 'examples/example.com.zone'
local records = rrparser.parse_file(fname)
assert(records ~= nil)
assert(#records == 10)
-- Parse file lines
local rc = 0
local parser = rrparser.new()
for line in io.lines(fname) do
	rc = parser:read(line .. '\n')
	assert(rc == 0)
	assert(parser.error_code == 0)
end
-- Parse record (custom callbacks)
parser = rrparser.new(function (p)
	local rr = p:current_rr()
	assert(rr.class == 1)
	assert(rr.ttl == 3600)
	assert(rr.owner == '\3foo\0')
	assert(rr.rdata == '\3bar\0')
end)
rc = parser:read("foo. IN 3600 NS bar.\n")
assert(rc == 0)
assert(parser.error_code == 0)
print('[ OK ] kdns.rrparser')
print('[ OK ] kdns')
