# The DNS library for LuaJIT

A contemporary DNS library using [LuaJIT FFI] focused on performance, and a lightning-fast [zone file parser][zscanner].
It supports all widely used DNS records (DNSSEC included) with a lean and mean API, including DNS primitives, messages and asynchronous I/O (including coroutines, TCP Fast Open and SO_REUSEPORT), and DNS over TLS.

## Installation

From LuaRocks:

```bash
luarocks install ljdns
```

From sources:


```bash
make check
make install
```

### Requirements

- [LuaJIT 2.x][libknot] - PUC-RIO Lua doesn't have the FFI module.
- [libknot 2.4 - 2.5][libknot] - isn't bundled, and must be [installed separately][knot-readme].
- ljsyscall >= 0.12
- lua-cjson >= 2.1.0
- gnutls >= 3.4.6 (if you want DNS/TLS)
- lmdb (if you want to use it)
- busted (for tests)
- luacheck (for tests)


## Tools

The library provides several utilities for convenience, see [tools/README.md](tools/README.md).

## Constants

There are numeric constants for DNS classes, types, opcodes and rcodes. Since they're constants, LuaJIT can inline them. You can convert them back to the text representation with `dns.tostring`.

```lua
-- Get constant numeric value
local opcode = dns.opcode.QUERY -- 0
-- Convert constant back to string
local name = dns.tostring.opcode[opcode] -- "QUERY"
-- Convert back to number
opcode = dns.opcode[name] -- 0
-- Examples of all constant tables
print(dns.class.IN)
print(dns.type.AAAA)
print(dns.opcode.IQUERY)
print(dns.rcode.NXDOMAIN)
print(dns.section.ANSWER)
print(dns.option.COOKIE)
```

## RR types

Record types are declared as numeric constants in `dns.type` table. There are symbolic constants for all used RR types as of today (not deprecated). For unknown/custom types, simply use their numeric value.

```lua
-- Returns 2 (number of NS type)
print(dns.type.NS)
-- Compare as simple numbers
if qtype == dns.type.AAAA then print('is AAAA question') end
-- Constants are numbers, they don't have implicit tostring() conversion
-- Use dns.tostring table to convert constants to text format
print(dns.tostring.type[2]) -- "NS"
print(dns.tostring.type[1]) -- "A"
-- Convert custom type to string
print(dns.tostring.type[55555]) -- "TYPE55555"
-- Check if type is a meta type
print(dns.type.ismeta(dns.type.A))
false
print(dns.type.ismeta(dns.type.AXFR))
true
```

## Domain names

Domain names are stored in a wire format as a sequence of labels prefixed by their length.
The library supports conversion between textual representation and wire format.

```lua
-- Read from wire format
local dname = dns.dname('\7example\3com')
-- Convert back to string using tostring()
assert(tostring(dname) == 'example.com.')
-- Read from textual representation 
dname = dns.dname.parse('example.COM')
-- Interpret as wire format
assert(dname == '\7example\3COM')
```

The library provides a handful of useful functions over domain names, use string package for more complex operations.

```lua
-- Count domain name labels
dname:labels()
-- Explode domain name labels
assert.same(dname:split(), {'example', 'com'})
-- Covert to lowercase
print(dname:lower())
-- Checks if dname is a child of parent
if dname:within('\3com') then print('child of com.') end
-- Checks if dname is a wildcard
if dname:wildcard() then print('yes, it is a wildcard') end
```

## RDATA

RDATA is stored as a simple binary string, the library contains a few helper functions for conversion from text format (the same as is used in RFC1035 zone files). A, AAAA, MX, NS, SOA, TXT have convenience functions:

```lua
-- Convenience for A RDATA (IPv4 address)
local rd_a = dns.rdata.a('1.2.3.4')
-- RDATA is a LuaJIT string with a fixed length
assert(rd_a == '\1\2\3\4')
assert(#rd_a == 4)
-- Convenience for MX record
assert(dns.rdata.mx('10 test') == '\0\10\4test\0')
-- Convenience for TXT record
assert(dns.rdata.txt('abcd') == '\4abcd')
```

The rest of the types can be parsed with generic interface.

```lua
-- Parse LOC type
dns.rdata.parse('LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m')
-- Parse SRV record
dns.rdata.parse('SRV 0 5 5060 sipserver.example.com.')
-- nil is returned on invalid text format
assert(dns.rdata.parse('SRV 0 5 zzzz') == nil)
```

RDATA wire format loses information about its type during transformation, it needs to be first inserted to RR set for wire to text conversion, read on how to print it.


### RDATA dissectors

There are several dissectors available for RDATA.

* SOA RDATA dissectors

```lua
local rata = dns.rdata.parse('SOA a.ns. nobody. 2016000000 1800 900 604800 86400')
print(dns.rdata.soa_primary_ns(rdata)) -- 'a.ns.'
print(dns.rdata.soa_mailbox(rdata))    -- 'nobody.'
print(dns.rdata.serial(rdata))         -- 2016000000
```

Adding new dissectors is easy thanks to duck-typing in Lua.

```lua
-- Install new dissector
dns.rdata.cname_target = function (rdata)
	rdata = ffi.cast('char *', rdata)
	return dns.dname(rdata, utils.dnamelen(rdata))
end
-- Dissect CNAME target
local rdata = dns.rdata.parse('CNAME next-name.')
print(dns.rdata.cname_target(rdata))   -- 'next-name.'
```

## RR sets

RR set is a set of RDATA with a common `owner`, `type`, `class`. As there is no special type for a single RR, it can be expressed as a RR set of size 1. RR set can be constructed programatically, or parsed from wire.

```lua
-- Construct RR set of 'com.' and type NS (IN class is implicit)
-- Owner is a domain name in wire format
local rr = dns.rrset('\3com', dns.type.NS)
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
rr:add(dns.rdata.ns('ns1.com'), 3600)
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

## DNS messages

DNS messages are defined in [RFC 1035, section 4. MESSAGES](http://tools.ietf.org/html/rfc1035). They contain 12 octets of header, question and a sequence of RR. As with dnames, RDATA and RR sets, it is backed by binary string of fixed length.

```lua
-- Create an empty packet of 512B with pseudo-random ID
local pkt = dns.packet(512)
-- Get message ID (returns number)
print(pkt:id())
-- Set message ID (accepts number, returns number)
assert(pkt:id(1234) == 1234)
-- Set OPCODE
pkt:opcode(dns.opcode.QUERY)
assert(pkt:opcode() == 0)
-- Set RCODE
pkt:rcode(dns.rcode.NOERROR)
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
pkt:question('\2cz', dns.type.SOA)
```

Packets are treated as bytestreams, record are organized in sections which must be written in order. This means that once an authority section is written, it's **not** possible to go back and write more records in answer section. If you need to write records out of order, keep them in a separate tables until finalization.

```lua
-- Section codes are in dns.section table {ANSWER, AUTHORITY, ADDITIONAL}
pkt:begin(dns.section.ANSWER)
-- Put RR in this answer (shortened method)
pkt:put(dns.rrset('\2cz', dns.type.A):add(dns.rdata.a('1.2.3.4'), 3600))
-- Verify RR count
assert(pkt:ancount() == 1)
-- End answer, begin authority
pkt:begin(dns.section.AUTHORITY)
local ns = dns.rrset('\2cz', dns.type.NS)
ns:add('\3ns1\2cz\0', 3600)
pkt:put(ns)
-- Attempt to write to answer again
pkt:begin(dns.section.ANSWER) -- WRONG, throws error
-- Finalize to Lua binary string
local wire = pkt:towire()
```

### EDNS

The EDNS OPT is a special type of RR, because it uses its fields for a different purpose. The library treats it as a RR with only minimal hand-holding, but provides a handful of convenience functions. It also **MUST** be the last RR in the ADDITIONAL section (with the exception of TSIG). This is where you can set maximum UDP payload and `DO` bit to signalize DNSSEC OK.

```lua
-- Create OPT RR (optional version, payload)
local opt = dns.edns.rrset(0, 4096)
-- Set "DNSSEC OK"
dns.edns.dobit(opt, true)
-- Add EDNS option (numeric code, binary string of data)
dns.edns.option(opt, 0x5, 'mydata')
-- Enter ADDITIONAL section, the OPT must be last in the packet
pkt:begin(dns.section.ADDITIONAL)
-- Write as any other packet
pkt:put(opt)
print(tostring(pkt))
```

As it's an API over binary string, it can be used for parsing packet from wire format as well.

```lua
-- Create packet over existing wire, it will not be allocated
local answer = dns.packet(#wire, wire)
-- Packet parser returns true|false depending on the result
if answer:parse() then print('success!') end
-- Set QR bit to signify answer
answer:qr(true)
-- Check if it's answer to original query
if answer:answers(pkt) then print('indeed') end
-- Write out the packet in text format (same as ISC dig)
tostring(answer)
-- Retrieve packet section copy as Lua table
local records = answer:section(dns.section.ANSWER)
for i, rr in ipairs(records) do
	print(rr)
end
-- Check EDNS OPT RR
if pkt.opt_rr ~= nil then
	local rr = pkt.opt_rr
	print(dns.edns.version(rr), dns.edns.dobit(rr))
	-- Check if it contains EDNS OPT code
	if dns.edns.has(rr, dns.option.COOKIE) then print('yes, has cookie') end
	-- Set and get an EDNS option
	dns.edns.option(dns.option.COOKIE, 'abcdefgh')
	assert(dns.edns.option(dns.option.COOKIE) == 'abcdefgh')
end
```

### TSIG

TSIG is not a property of packet but a pairing of TSIG key with a signer state. It has two operations - *sign()*, and *verify()* and keeps digest state between requests. This means that if you verify a query and use the same TSIG for signing response, it will remember the query digest for signing.

```lua
-- Create TSIG signer from string, same format as ISC dig
local tsig_client = dns.tsig('keyname:hmac-md5:Wg==')
local tsig_server = tsig_client:copy()
-- Sign packet, TSIG remembers 'last signed' and query digest
assert(tsig_client:sign(pkt))
-- Authenticate query
assert(tsig_server:verify(pkt))
-- Create answer and sign it
local answer = pkt:copy()
answer:qr(true)
assert(tsig_server:sign(answer))
-- Verify by client
assert(tsig_client:verify(answer))
```

### DNSSEC

The library provides an API for online signing and verification of records. For that it needs zone signing key (ZSK) and preferably key signing key (KSK) if you don't plan to use the key forever. KSK can be the same key as ZSK, but that will make rollovers more error prone and complicated. You can load private keys from PEM, and public keys (for verification) from either DNSKEY RDATA or PEM.

```lua
local dnssec = require('dns.dnssec')
-- Create key for verification
local dnskey = dns.rrset(...)
local key = dnssec.key()
assert(key:rdata(dnskey:rdata(0)))
assert(key:can_verify() == true) -- Yes, we have pubkey
assert(key:can_sign() == false)  -- No, we don't have private key
-- Alternatively, create key from PEM
key:algo(dnssec.algo.ecdsa_p256_sha256) -- PEM requires algorithm to be set
assert(key:pubkey(pem_data))            -- Raw pubkey in PEM format

-- Create key for signing
local key = dnssec.key()
key:algo(dnssec.algo.ecdsa_p256_sha256) -- PEM requires algorithm to be set
key:pubkey(pem_data)                    -- Raw privkey in PEM format
assert(key:can_sign() == true)          -- Yes

-- Keys have readable properties
print(key:tag())       -- RFC4034 KeyTag
print(key:name())      -- Key owner (domain name)
print(key:flags())     -- Key flags (RFC4034, for checking SEP bit)
print(key:protocol())  -- Key protocol (RFC4034)
print(key:algo())      -- Key algorithm (RFC4034, see dnssec.algo table)
```

For signing and verification, caller needs to create a *signer* associated with a key.
Signer provides an interface that can work either over raw bytes or RR sets.

```lua
-- Create signer from key with loaded private key
assert(key:can_sign() == true)  -- We need a key that can sign
local signer, err = dnssec.signer(key)
assert(signer, err)
-- Signer is associated with the key now, let's sign something
local rr = dns.rrset('\7example', dns.type.TXT)
rr:add('DNSSEC is easy', 60)  -- Can't sign empty RR
local rrsig, err = signer:sign(rr) -- Signer accepts RR, produces RRSIG
assert(rrsig, err)
-- The signer uses current time and covered record TTL as default,
-- but the caller can specify its own inception and expiration time
-- Sign the record with expiration 1 hour from now
rrsig = signer:sign(rr, 3600, os.time())
```

Now that we have signature created, we can verify it using the same key.

```lua
-- Verify RR against its RRSIG using current ZSK
assert(signer:verify(rr, rrsig))
```

Authenticated denials of non-existence are somewhat supported - RFC4470 *White lies* and
NSEC shotgun, where closest successor of QNAME is returned with NSEC bitmap listing all types but QTYPE.
There are no helpers for off-line signed zones, where NSEC chains must be built first in
order to determine next closer record and no wildcard expansion proof. You're on your own.

```lua
local owner = dns.dname('\7example')
-- Deny existence of 'example.' and type A
local nsec = dnssec.denial(owner, dns.type.A)
-- Names that do not exist are simplified, as only NSEC and RRSIG can exist
local nsec = dnssec.denial(owner, dns.type.A, true)
```

### Caveats

There is a caveat with packet parsing, as LuaJIT [doesn't GC cdata](http://luajit.org/ext_ffi_semantics.html#gc), the Lua string with a wire must be referenced during the lifetime of the packet.

```lua
-- WRONG, this will GC the wire while it's being read
local pkt = dns.packet(12, '\0\0\0\0\0\0\0\0\0\0\0\0')

-- RIGHT, reference to wire is kept during the pkt lifetime
local wire = '\0\0\0\0\0\0\0\0\0\0\0\0'
local pkt = dns.packet(#wire, wire)
```

Library also provides hexdump of binary string for debugging purposes or bisection.

```lua
> dns.hexdump(pkt:towire())
00000000  04 D2 03 30 00 01 00 01 00 00 00 01 04 74 65 73  .?.0.........tes
00000010  74 00 00 06 00 01 03 63 6F 6D 00 00 02 00 01 00  t......com......
00000020  00 0E 10 00 06 04 74 65 73 74 00 03 63 6F 6D 00  ......test..com.
00000030  00 01 00 01 00 00 0E 10 00 04 01 02 03 04        ..............
```

## Zone files

The library comes with a RFC1035 zone file parser with a very simple API.
If you want to build something resembling a sorted record set or filter it, skip to the next section.

You can parse the zone file into a table of records.

```lua
local rrparser = require('dns.rrparser')
local records = rrparser.parse_file('example.com.zone')
for i, rr in ipairs(records) do
	print(rr.owner, rr.type, len(rr.rdata))
end
```

Or parse zone file into a stream of records, see [zscanner structure][zscanner-api] for reference.
This is much faster for large zones, as it doesn't require you store and copy every record.

```lua
local parser = rrparser.new()
assert(parser:open(zonefile))
while parser:parse() do
	print(dns.todname(parser.r_owner, parser.r_owner_length), parser.r_type, parser.r_data_length)
	-- Build a real RRSet
	local owner = dns.todname(parser.r_owner, parser.r_owner_length)
	local rr = dns.rrset(owner, parser.r_type)
	rrset:add(ffi.string(parser.r_data, parser.r_data_length), parser.r_ttl)
end
```

The same interface can be also used for parsing zones from strings.

```lua
local parser = rrparser.new()
local ok, err = parser:parse('foo. 3600 IN A 1.2.3.4\n')
if ok then
	print(dns.todname(parser.r_owner, parser.r_owner_length), parser.r_type, parser.r_data_length)
else
	print(err)
end
```

## Zone sifting

Sift is a higher-level interface over zone parser that allows you to either filter the results
using your own or predefined filters, and capture the results. This can be used to build a sorted
set of RR sets, i.e. a *"zone"*.

The results can be either captured in [LMDB][lmdb] on-disk, as a sorted set in memory, printed out, converted to JSON, or passed to caller-provided closure for any other custom processing.

```lua
local sift = require('dns.sift')
-- Print records in the zone
sift.zone(zone, sift.printer())
-- Load text zone into JSON
local cap, err = sift.zone(zone, sift.jsonify())
-- Load text zone into sorted set
local set, err = sift.zone(zone, sift.set())
if not set then error(err) end
-- Load text zone into LMDB
local env = assert(lmdb.open('.', 'writemap, mapasync'))
local set, inserted, db = sift.zone(zone, sift.lmdb(env))
```

### Working with sorted set

The sorted set is structured, so we can perform further actions with it like sort/resort or lookups.
Note that the set is sorted in terms of [RFC4034](https://tools.ietf.org/html/rfc4034#section-6.1) canonical name ordering and may be used for DNSSEC purposes. The search algorithm is a binary search to keep things simple, while still getting a decent performance.

```lua
-- Sort the set captured from previous example
set:sort()
-- Search a name, the result is a lesser or equal RR
-- This allows searching for exact match or predecessor
local query = dns.dname('\5query\3com')
local rr = set:search(query)
if rr and query:equals(rr:owner()) then
	print('result:', rr)
end
-- Fetch a searcher closure specialized to current set length
-- This allows a faster search if the set size doesn't change
local searcher = set:searcher()
local rr = searcher(qname)
```

### Working with LMDB storage

LMDB is file-backed key-value storage, that means it can also be persistent so you can keep results
between program execution or do fast resumption. You want this backend if read performance is a key, or the data will be shared between several instances. Unlike sorted set, the interface is based around transactions and cursors to get consistent view of the data, and doesn't need resorting after insertion. The value is also generic array of bytes, so you can store anything. Records map *"search keys"*,
composed of domain name and type, to raw record data stored as `{u32 ttl, u8 ttl[...]}`.

```lua
-- Start a read transaction and read a key
local txn = assert(set:txn(db, 'rdonly'))
-- Convert to search key
local key, len = utils.searchkey('\5query\3com', dns.type.AAAA)
-- Retrieve stored value
local value = txn:get(lmdb.val_t(len, key))
-- Deserialize (example)
local ttl = ffi.new('uint32_t [1]')
ffi.copy(ttl, value.data, ffi.sizeof(ttl))
local rdata = ffi.string(value.data + ffi.sizeof(ttl), value.size - ffi.sizeof(ttl))
-- Abort read transaction
txn:abort()
```

You can also use the database to read and write generic key-value pairs.
Inserting to database requires write transaction, otherwise it's straightforward.

```lua
local txn = assert(set:txn(db))
txn:put('test', 'val')          -- Inserted `test => val`
print(tostring(txn:get('test')) -- Values support tostring()
```

Iterating over database requires transaction cursors. They are compatible with
both `pairs()` and `ipairs()` iterators in Lua.

```lua
local cur = txn:cursor()
for i,v in ipairs(cur) do
	print(i, tostring(v))
end
cur:close()
```

### Filter algebra

The second part of sifting is filtering functionality. This is where LuaJIT shines,
as it can compile the filter into efficient machine code on runtime.

```lua
-- Filter all records at/below "query.is"
sift.zone(zone, sift.printer(), sift.makefilter('*.query.is'))
-- Chain filters with logical AND
sift.zone(zone, sift.printer(), sift.makefilter({'*.query.is', 'type=SOA'}))
```

Each filter has field, operator and operand. The field may be implicit
in some cases, i.e. expressions `*.query.is` and `owner=*.query.is` have the same meaning.
Same for `SOA` and `type=SOA` for known DNS record types.

The algebra supports most Lua comparison operators: `=, ~=, <, <=, >, >=`.
For example `ttl<=60` requires TTL to be lesser or equal than 60s,
and `owner=query.is` matches only RRs with equivalent owner.

Examples:

```lua
owner=*.query.is -- Match all names at/below query.is
owner~=query.is  -- Match all names except query.is
type=NS          -- Match all records with NS type
type~=RRSIG      -- Match all records except RRSIGs
ttl<=3600        -- Match all records with TTL lower or equal 1h
```

The filter may also search the righthand-side of the record by looking for
patterns in RDATA. It is possible to look for textual representation or
pattern in wire format. For example:

```lua
-- Match A records whose address is 1.2.3.4
rdata=A(1.2.3.4)
-- Match NS records with "query.is" found in target
rdata=NS(query.is)
```

These are **not** equivalence matches, but a pattern search. The `NS(query.is)` would match
all of the following:

```
example.            	3600	NS	ns.query.is.
example.            	3600	NS	a.ns.query.is.
example.            	3600	NS	query.is.
```

But not these:

```
example.            	3600	NS	query.is.bad.
```

This is because an expression `NS(query.is)` searches for a domain name `\5query\2is\0` that is terminated by root label, that occurs only on the domain name end. This is useful to know, because it can be used to find matching subdomains.

If you want to search for pattern in RDATA in wire format, do not prefix it with the type for interpretation.
For example:

```lua
rdata=\x02cz        -- Match all RDATA containing "\2cz" in wire format
rdata~=\x01\x02\x03 -- Match all RDATA *not* containing a sequence of bytes
```

A real world example would be to find all domains, that are hosted at `hoster.is`.

```lua
sift.zone(zone, sift.printer(), sift.makefilter('NS(hoster.is)'))
```

### Performance


LuaJIT 2.1+ is recommended for performance reasons. To get a rough idea about the performance on your
zone, use the `examples/bench.lua` script. Here's an example on a synthetic zone with 1 million records:

```lua
$ luajit examples/bench.lua zones/example.com.1m 
bench: sortedset
load: 696.21 msec (1000010 rrs)
sort: in 1242.84 msec
search: 1598646 ops/sec
bench: lmdb
load: 1089.06 msec (1000010 rrs)
search: 5416827 ops/sec
```

This means it parsed and loaded a zone with million records into memory under 2 seconds, and is able to perform over 1.5M lookups per second over sorted set, and 5.4M lookups per second with LMDB.

## Non-blocking I/O

The library comes with simple non-blocking socket I/O and coroutines, this means you can write sequential code and get free concurrency when coroutine would block instead. As the coroutines are
scoped, you can nest coroutines and tie their lifetime to sockets they block on.

The asynchronous I/O is based on [ljsyscall][ljsyscall] and uses `epoll/kqueue` when possible. It also supports [TCP Fast Open][tcp-fastopen] and `SO_REUSEPORT` when available.

You can create coroutines, very much like in Go language.

```lua
local nb = require('dns.nbio')
nb.go(function ()
	print('Hi from Alice!')
end)
nb.go(function ()
	print('Hi from Bob!')
end)
assert(nb.run())
```

You don't have to let coroutines take over main program loop and instead use a poll style API.

```lua
nb.go(function ()
	print('Hi from Bob!')
end)
assert(nb.step(1)) -- Only one step with 1s timeout
```

### TCP example

The `nbio` library allows you to create non-blocking sockets with `nbio.socket()` function.
The sockets follow the same API as OpenResty [non-blocking sockets](https://github.com/openresty/lua-nginx-module#ngxsocketudp) or [LuaSocket](http://w3.impa.br/~diego/software/luasocket/reference.html).

These sockets can be used anywhere inside coroutines, not in the main thread as it cannot be suspended if socket needs to wait for readiness. Let's make a listener and a client and make them exchange messages.

```lua
local master = nb.socket('inet', 'stream')
master:bind('127.0.0.1', 0)
nb.go(function ()                   -- First coroutine acts as server
	local bob = master:accept()     -- Accept TCP connection
	bob:send('PING')                -- Send query
	local msg, err = bob:receive(4) -- Receive response
	assert(msg == 'PONG')
end)

local host, port = master:getsockname()
nb.go(function ()
	local alice = nb.socket('inet', 'stream') -- Make unbound TCP socket
	alice:connect(host, port)                 -- Connect to TCP server
	local msg, err = alice:receive(4)         -- Wait for query
	assert(msg == 'PING')
	alice:send('PONG')                        -- Send back response
end)

assert(nb.run(1))
```

### Using TCP Fast Open

For bound sockets it is enabled automatically. If you want to initiate a TFO connection,
pass a message and address to `connect()` call in addition to host and port. If possible,
the library will start TFO or fall back to `connect() + send()` transparently.

```lua
nb.go(function()
	local client = nb.socket('inet', 'stream') -- Make unbound TCP socket
	client:connect('127.0.0.1', 8080, 'PING')  -- Attempt TFO or connect + send
	local msg, err = client:recv(4)            -- Receive response (client is connected)
	print('Received:', msg, err)
end)
```

### UDP example

Both connected and unconnected UDP sockets are supported. Connected sockets are used in the same way
as TCP sockets in a way that address doesn't have to be provided.

```lua
nb.go(function()
	local client = nb.socket('inet', 'dgram') -- Make connected UDP socket
	client:connect('193.0.14.129', 53)        -- Alternative to setpeername()
	-- Make root NS question
	local msg = dns.packet(64)
	msg:question('\0', dns.type.NS)
	client:send(msg:towire())                 -- Send DNS message and receive response
	local msg = client:receive()
	print('received', dns.hexdump(msg))
end)
```

### Composing UDP servers

The coroutines provide you with an easy concurrency for UDP sockets without callbacks,
allowing for push-pull, circular queue and single-listener modes.

```lua
local udp = nb.socket('127.0.0.1', 53) -- Make UDP server socket
-- Writer
local function serve(sock, msg, saddr)
	-- Zero-copy parse and flip QR=1
	local pkt = dns.packet(#msg, msg)
	assert(pkt:parse())
	pkt:qr(true)
	-- Send the packet back
	nb.udpsend(msg, saddr)
end
-- Reader
nb.go(function ()
	while true do
		local msg, addr = nb.udprecv(udp)
		local ok, err = pcall(serve, msg, addr)
		if not ok then print(err) end
	end
end)
```

### Gotchas

Performance PRO TIP is to avoid creating closures in loops, as that aborts traces. Instead, create the closure beforehand and reuse it in loop with an arbitrary number of parameters.

```lua
-- Create a function elsewhere
local function serve(sock, msg)
	print('received', #msg)
end
-- Now reuse the closure "serve()"
while true do
	assert(go(serve, sock, nb.recv(sock)))
end
```

## DNS over TLS

The library supports upgrading TCP connections to [RFC7858][rfc7858] DNS over TLS for both server and client. The `dig.lua` example has demo client-side code with `+tls` option, it supports pipelining with TLS too. Usage is straightforward, each accepted connection must be upgraded to TLS prior its use:

```lua
local tls = require('dns.tls')
-- Open X.509 credentials
local cred = tls.creds.x509 {
	certfile = 'test.crt',
	keyfile = 'test.key',
}
-- Upgrade to TLS with X.509 certificate
local server = nb.socket('inet', 'stream')
server:bind('127.0.0.1', 53)
nb.go(function()
	local client = server:accept()
	client = assert(tls.server(client, cred))
	local ret, err = client:receive()
	print('tls received:', ret, err)
end)
assert(nb.run())
```

Client code works similarly, unfortunately DNS/TLS cannot be used together with [TFO][tcp-fastopen] because the handshake is done by the underlying library (GnuTLS) over already connected socket.

```lua
-- Connect to remote server
local client = nb.socket('inet', 'stream')
client:connect(...)
-- Upgrade to TLS without X.509 client certificate
client = assert(tls.client(client, 'x509'))
```

Client can also provide client certificate and provide trusted CA bundle, however currently the server in this library doesn't do peer verification, so keep in mind that it's not good for production use.

```lua
-- Upgrade to TLS with X.509 client certificate
client = assert(tls.client(client, tls.creds.x509 {
	cafile   = 'ca-cert.pem', -- CA bundle in PEM format
	certfile = 'client.crt',  -- Client certificate
	keyfile  = 'client.key',  -- Client key
}))
```

[LuaJIT FFI]: http://luajit.org/ext_ffi.html
[LuaJIT]: http://luajit.org
[libknot]: https://github.com/CZ-NIC/knot/tree/master/src/libknot
[zscanner]: https://github.com/CZ-NIC/knot/tree/master/src/zscanner
[zscanner-api]: https://github.com/CZ-NIC/knot/blob/master/src/zscanner/scanner.h#L86
[knot-readme]: https://github.com/CZ-NIC/knot/blob/master/README
[ljsyscall]: http://myriabit.com/ljsyscall/
[tcp-fastopen]: https://tools.ietf.org/html/draft-ietf-tcpm-fastopen-10
[rfc7858]: https://datatracker.ietf.org/doc/rfc7858
[lmdb]: https://symas.com/products/lightning-memory-mapped-database/
