local kdns = require('kdns')

-- Test constants
assert(kdns.class.IN == 1)
assert(kdns.type.NS == 2)
assert(kdns.rcode.SERVFAIL == 2)

-- Test domain names
local dname = kdns.dname('\7example\3com')
assert(dname ~= nil)
assert(tostring(dname) == 'example.com.')
dname = kdns.dname.parse('example.COM')
assert(dname == '\7example\3COM')
assert(dname:labels() == 2)
assert(dname:lower() == '\7example\3com')

-- Test RDATA
assert(kdns.rdata.parse('A') == nil)
assert(kdns.rdata.parse('A asdf') == nil)
assert(kdns.rdata.parse('NS test') == '\4test\0')
assert(kdns.rdata.a('1.2.3.4') == '\1\2\3\4')
assert(kdns.rdata.mx('10 test') == '\0\10\4test\0')
assert(kdns.rdata.txt('abcd') == '\4abcd')

-- Test RR sets
local rrset = kdns.rrset('\3com', kdns.type.NS)
assert(rrset ~= nil)
assert(rrset.owner == '\3com')
assert(rrset.class == kdns.class.IN)
assert(rrset.type  == kdns.type.NS)
assert(rrset.rr.count == 0)
rrset:add(kdns.rdata.ns('test'), 3600)
assert(rrset.rr.count == 1)
assert(rrset:rdata(0) == '\4test\0')

-- Test packets
local pkt = kdns.packet(512)
assert(pkt:id(1234) == 1234)
assert(pkt ~= nil)
assert(pkt:question('\4test', kdns.type.SOA) == 0)
assert(pkt:begin(kdns.section.ANSWER) == 0)
assert(pkt:put(rrset) ~= nil)
assert(pkt:begin(kdns.section.ADDITIONAL) == 0)
assert(pkt:put(kdns.rrset('\3com', kdns.type.A):add(kdns.rdata.a('1.2.3.4'), 3600)) ~= nil)
print(pkt)
kdns.hexdump(pkt:towire())

print('kdns ok')
