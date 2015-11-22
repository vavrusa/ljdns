The DNS library for LuaJIT
==========================

A contemporary DNS library using [LuaJIT FFI] focused on performance, and a lightning-fast [zone file parser][zscanner].
It supports all widely used DNS records (DNSSEC included) with a lean and mean API, including DNS primitives, messages and I/O.

Requirements
------------

- [LuaJIT]. Regular Lua doesn't have the FFI module.
- [libknot][libknot] isn't bundled, and must be [installed separately][knot-readme].

Installation
------------

```bash
make check
make install
```

Performance
-----------

Performance is good, no measurements yet.

Constants
---------

There are numeric constants for DNS classes, types, opcodes and rcodes. Since they're constants, LuaJIT can inline them. You can convert them back to the text representation with `kdns.tostring`.

```lua
-- Get constant numeric value
local opcode = kdns.opcode.QUERY -- 0
-- Convert constant back to string
local name = kdns.tostring.opcode[opcode] -- "QUERY"
-- Convert back to number
opcode = kdns.opcode[name] -- 0
-- Examples of all constant tables
print(kdns.class.IN)
print(kdns.type.AAAA)
print(kdns.opcode.IQUERY)
print(kdns.rcode.NXDOMAIN)
print(kdns.section.ANSWER)
```

RR types
--------

Record types are declared as numeric constants in `kdns.type` table. There are symbolic constants for all used RR types as of today (not deprecated). For unknown/custom types, simply use their numeric value.

```lua
-- Returns 2 (number of NS type)
print(kdns.type.NS)
-- Compare as simple numbers
if qtype == kdns.type.AAAA then print('is AAAA question') end
-- Constants are numbers, they don't have implicit tostring() conversion
-- Use kdns.tostring table to convert constants to text format
print(kdns.tostring.type[2]) -- "NS"
print(kdns.tostring.type[1]) -- "A"
-- Convert custom type to string
print(kdns.tostring.type[55555]) -- "TYPE55555"
```

Domain names
------------

Domain names are stored in a wire format as a sequence of labels prefixed by their length.
The library supports conversion between textual representation and wire format.

```lua
-- Read from wire format
local dname = kdns.dname('\7example\3com')
-- Convert back to string using tostring()
assert(tostring(dname) == 'example.com.')
-- Read from textual representation 
dname = kdns.dname.parse('example.COM')
-- Interpret as wire format
assert(dname == '\7example\3COM')
```

The library provides a handful of useful functions over domain names, use string package for more complex operations.

```lua
-- Count domain name labels
dname:labels()
-- Covert to lowercase (in-place)
print(dname:lower())
-- Checks if dname is a child of parent
if dname:within('\3com') then print('child of com.') end
```

RDATA
-----

RDATA is stored as a simple binary string, the library contains a few helper functions for conversion from text format (the same as is used in RFC1035 zone files). A, AAAA, MX, NS, SOA, TXT have convenience functions:

```lua
-- Convenience for A RDATA (IPv4 address)
local rd_a = kdns.rdata.a('1.2.3.4')
-- RDATA is a LuaJIT string with a fixed length
assert(rd_a == '\1\2\3\4')
assert(#rd_a == 4)
-- Convenience for MX record
assert(kdns.rdata.mx('10 test') == '\0\10\4test\0')
-- Convenience for TXT record
assert(kdns.rdata.txt('abcd') == '\4abcd')
```

The rest of the types can be parsed with generic interface.

```lua
-- Parse LOC type
kdns.rdata.parse('LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m')
-- Parse SRV record
kdns.rdata.parse('SRV 0 5 5060 sipserver.example.com.')
-- nil is returned on invalid text format
assert(kdns.rdata.parse('SRV 0 5 zzzz') == nil)
```

RDATA wire format loses information about its type during transformation, it needs to be first inserted to RR set for wire to text conversion, read next paragraph.

RR sets
-------

RR set is a set of RDATA with a common `owner`, `type`, `class`. As there is no special type for a single RR, it can be expressed as a RR set of size 1. RR set can be constructed programatically, or parsed from wire.

```lua
-- Construct RR set of 'com.' and type NS (IN class is implicit)
-- Owner is a domain name in wire format
local rr = kdns.rrset('\3com', kdns.type.NS)
-- RR set has owner, type, class
print(rr:owner(), rr:type(), rr:class())
-- It can be converted back to string
tostring(rr) -- "com.	IN	NS"
-- RR set is IMMUTABLE, as the internals are GC-unaware
assert(pcall(function() rr.owner = nil end) == false)
```

RDATA may be inserted or extracted from the set. Inserted RDATA isn't checked for validity,
use RDATA constructors to make sure it is valid. RDATA in set are indexed from `0`.

```lua
-- Insert RDATA to NS RR set, second optional argument is TTL
rr:add(kdns.rdata.ns('ns1.com'), 3600)
-- First record defines RR set default TTL (0 if empty)
rr:ttl() -- 3600
-- You can insert RDATA in wire format, TTL is reused from first entry if nil
rr:add('\3ns2\3com\0')
-- RR set count is represented by its length
assert(#rr == 2)
-- Retrieve first RDATA in wire format
assert(rrset:rdata(0) == '\3ns1\3com0')
-- Retrieve single record as Lua table, this is MUTABLE
local first = rrset:get(0)
print(rr.owner, rr.ttl, rr.class, rr.type, rr.rdata)
```

Unlike RDATA, RR sets may be converted back to text format. You can parse whole records from text using zone file parser, see "Zone files".

```lua
> print(tostring(rrset))
com.                	3600	NS	ns1.com.
com.                	3600	NS	ns2.com.
```

DNS messages
------------

DNS messages are defined in [RFC 1035, section 4. MESSAGES](http://tools.ietf.org/html/rfc1035). They contain 12 octets of header, question and a sequence of RR. As with dnames, RDATA and RR sets, it is backed by binary string of fixed length.

```lua
-- Create an empty packet of 512B with pseudo-random ID
local pkt = kdns.packet(512)
-- Get message ID (returns number)
print(pkt:id())
-- Set message ID (accepts number, returns number)
assert(pkt:id(1234) == 1234)
-- Set OPCODE
pkt:opcode(kdns.opcode.QUERY)
assert(pkt:opcode() == 0)
-- Set RCODE
pkt:rcode(kdns.rcode.NOERROR)
assert(pkt:rcode() == 0)
-- Get AA flag value
print(pkt:aa())
-- Set AA flag value, accepts boolean
pkt:aa(true)
-- Print out values of all flags
for _, flag in pairs({'rd', 'tc', 'aa', 'qr', 'cd', 'ad', 'ra'}) do
	print(flag, pkt[flag](pkt))
end
-- Set packet question (return 0 on success)
pkt:question('\2cz', kdns.type.SOA)
```

Packets are treated as bytestreams, record are organized in sections which must be written in order. This means that once an authority section is written, it's **not** possible to go back and write more records in answer section. If you need to write records out of order, keep them in a separate tables until finalization.

```lua
-- Section codes are in kdns.section table {ANSWER, AUTHORITY, ADDITIONAL}
pkt:begin(kdns.section.ANSWER)
-- Put RR in this answer (shortened method)
pkt:put(kdns.rrset('\2cz', kdns.type.A):add(kdns.rdata.a('1.2.3.4'), 3600))
-- Verify RR count
assert(pkt:ancount() == 1)
-- End answer, begin authority
pkt:begin(kdns.section.AUTHORITY)
local ns = kdns.rrset('\2cz', kdns.type.NS)
ns:add('\3ns1\2cz\0', 3600)
pkt:put(ns)
-- Attempt to write to answer again
pkt:begin(kdns.section.ANSWER) -- WRONG, throws error
-- Finalize to Lua binary string
local wire = pkt:towire()
```

The EDNS OPT is a special type of RR, because it uses its fields for a different purpose. The library treats it as a RR with only minimal hand-holding, but provides a handful of convenience functions. It also **MUST** be the last RR in the ADDITIONAL section (with the exception of TSIG). This is where you can set maximum UDP payload and `DO` bit to signalize DNSSEC OK.

```lua
-- Create OPT RR (optional version, payload)
local opt = kdns.edns.rrset(0, 4096)
-- Set "DNSSEC OK"
kdns.edns.dobit(opt, true)
-- Add EDNS option (numeric code, binary string of data)
kdns.edns.option(opt, 0x5, 'mydata')
-- Enter ADDITIONAL section, the OPT must be last in the packet
pkt:begin(kdns.section.ADDITIONAL)
-- Write as any other packet
pkt:put(opt)
print(tostring(pkt))
```

As it's an API over binary string, it can be used for parsing packet from wire format as well.

```lua
-- Create packet over existing wire, it will not be allocated
local answer = kdns.packet(#wire, wire)
-- Packet parser returns true|false depending on the result
if answer:parse() then print('success!') end
-- Set QR bit to signify answer
answer:qr(true)
-- Check if it's answer to original query
if answer:answers(pkt) then print('indeed') end
-- Write out the packet in text format (same as ISC dig)
tostring(answer)
-- Retrieve packet section copy as Lua table
local records = answer:section(kdns.section.ANSWER)
for i, rr in ipairs(records) do
	print(rr.owner, rr.ttl, rr.class, rr.type, rr.rdata)
end
-- Check EDNS OPT RR
if pkt.opt then
	local rr = pkt.opt
	print(kdns.edns.version(rr), kdns.edns.dobit(rr))
	-- Check if it contains EDNS OPT code
	if kdns.edns.option(rr, 0x05) then print('yes, has 0x5 option') end
end
```

TODO: TSIG
----------

There is a caveat with packet parsing, as LuaJIT [doesn't GC cdata](http://luajit.org/ext_ffi_semantics.html#gc), the Lua string with a wire must be referenced during the lifetime of the packet.

```lua
-- WRONG, this will GC the wire while it's being read
local pkt = kdns.packet(12, '\0\0\0\0\0\0\0\0\0\0\0\0')

-- RIGHT, reference to wire is kept during the pkt lifetime
local wire = '\0\0\0\0\0\0\0\0\0\0\0\0'
local pkt = kdns.packet(#wire, wire)
```

Library also provides hexdump of binary string for debugging purposes or bisection.

```lua
> kdns.hexdump(pkt:towire())
00000000  04 D2 03 30 00 01 00 01 00 00 00 01 04 74 65 73  .?.0.........tes
00000010  74 00 00 06 00 01 03 63 6F 6D 00 00 02 00 01 00  t......com......
00000020  00 0E 10 00 06 04 74 65 73 74 00 03 63 6F 6D 00  ......test..com.
00000030  00 01 00 01 00 00 0E 10 00 04 01 02 03 04        ..............
```

I/O
---

There are convenience functions using [LuaSocket](http://w3.impa.br/~diego/software/luasocket/) for simple DNS server or clients. Use faster FFI bindings for high-performance applications.

```lua
-- This is how you write a simple ISC dig clone
local host = '2001:503:ba3e::2:30'
local query = kdns.packet(512)
query:question(kdns.dname.parse('com'), kdns.type['NS'])
-- Perform I/O and parse answer
local wire = kdns.io.query(query:towire(), host)
local answer = kdns.packet(#wire, wire)
if not answer then error('no answer') end
if not answer:parse() then error('invalid message') end
print(answer)
print('\n;; MSG SIZE  rcvd:', #wire)
```

The `kdns.io` supports only `send`, `recv` and `query` over UDP or TCP.

```lua
-- Get connected socket to peer (TCP)
local tcp_sock = kdns.io.client('127.0.0.1', true)
-- Send message
kdns.io.send(query:towire(), tcp_sock)
-- Receive answer
local answer = kdns.io.recv(tcp_sock)
```

Zone files
----------

For example, you can parse the zone file into a table of records.

```lua
local rrparser = require('kdns.rrparser')
local records = rrparser.parse_file('example.com.zone')
for i, rr in ipairs(records) do
	print(rr.owner, rr.type, len(rr.rdata))
end
```

Or parse input by chunks, see [zscanner structure][zscanner-api] for reference.

```lua
local parser = rrparser.new()
local rc = parser:read('foo. 3600 IN A 1.2.3.4\n')
if rc == 0 then
	print(parser.r_type, parser.r_data_length)
end
```

Or use callbacks for multiple chunks.

```lua
local addr_records = {}
local parser = rrparser.new(function (parser)
	if parser.r_type == 1 then
		table.insert(addr_records, parser:current_rr())
	end
end)
for line in io.lines('example.com.zone') do
	local rc = parser:read(line .. '\n')
	if rc ~= 0 then
		error('line', parser.line_counter, parser:last_error())
	end
end
```

[LuaJIT FFI]: http://luajit.org/ext_ffi.html
[LuaJIT]: http://luajit.org
[libknot]: https://github.com/CZ-NIC/knot/tree/master/src/libknot
[zscanner]: https://github.com/CZ-NIC/knot/tree/master/src/zscanner
[zscanner-api]: https://github.com/CZ-NIC/knot/blob/master/src/zscanner/scanner.h#L86
[knot-readme]: https://github.com/CZ-NIC/knot/blob/master/README
