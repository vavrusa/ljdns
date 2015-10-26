The DNS library for LuaJIT
==========================

A contemporary DNS library using [LuaJIT FFI] focused on performance, and a lightning-fast [zone file parser][zscanner].
It supports all widely used DNS records (DNSSEC included), and sports a lean and mean API, including DNS primitives.

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

Domain names
------------

RR types
--------

RR sets
-------

DNS messages
------------

I/O
---

Zone files
----------

For example, you can parse the zone file into a table of records.

```lua
local zonefile = require 'zonefile'
local records = zonefile.parse_file('example.com.zone')
for i = 1, #records do
	local rr = records[i]
	print(rr.owner, rr.type, len(rr.rdata))
end
```

Or parse input by chunks, see [zscanner structure][zscanner-api] for reference.

```lua
local zonefile = require 'zonefile'
local parser = zonefile.parser()
local rc = parser:read('foo. 3600 IN A 1.2.3.4\n')
if rc == 0 then
	print(parser.r_type, parser.r_data_length)
end
```

Or use callbacks for multiple chunks.

```lua
local zonefile = require 'zonefile'
local addr_records = {}
local parser = zonefile.parser(function (parser)
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
