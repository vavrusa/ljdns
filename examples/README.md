The KDNS tools
==============

The LuaJIT DNS library comes with a handy set of tools and building blocks.

dig(1) clone
------------

Supports most widely used parameters and options of ISC DiG, nothing fancy but useful
for quick diagnostics.

```bash
# Get the basics done
$ luajit dig.lua NS example.com +dnssec
$ luajit dig.lua -x ::1 +bufsize=1280
```

zq - a jq for zone files
------------------------

Or also a strange misfit similar to grep(1) and awk(1) specialized for RFC1035 zone files.
This is a tool built on DNS library [zone sifting](../README.md).
It can parse a zone file, apply filters and transform them.

This is handy for various use cases:

```bash
# Prettify zone file and sort it canonically
$ luajit zq.lua -s example.com.zone
# Parse zone and transform it into JSON
$ luajit zq.lua -f json example.com.zone
# Extract only SOA from zone and turn it into JSON
# Hint: see "Zone sifting" for introduction into filter rules
$ luajit zq.lua -f json SOA example.com.zone
# Feed it into jq(1) for further transformation
$ luajit zq.lua -f json SOA example.com.zone | jq '.[0].rdata'
# Use it as an offline query tool into zone data
# Query: which domains are hosted by "bighoster.is" ?
$ luajit zq.lua -f json NS(bighoster.is) example.com.zone | jq -r '.[].owner'
```

namepile - poor man's zone transfer server
------------------------------------------

This is a simple daemon that provides zone transfers for a pile of zones
It expects to find files ending with .zone, zones are parsed and streamed on demand,
so free startup time and no memory requirements.

```bash
$ mkdir pile
$ echo "$ORIGIN example" > pile/example.zone
$ echo "@ 3600 IN SOA dns hostmaster 0 10800 3600 1209600 60" >> pile/example.zone
$ echo -e "@ 3600 IN NS ns1\nns1 3600 IN A 1.2.3.4" >> pile/example.zone
$ namepile.lua -v pile @127.0.0.1#4242 &
$ dig.lua AXFR @127.0.0.1#4242 example.
```