The ljdns tools
===============

The LuaJIT DNS library comes with a handy set of tools and building blocks.

How to get them?
----------------

Either clone and install from repo or through LuaRocks.

```bash
$ luarocks install ljdns
$ ldig -h
Usage: ldig [options] [@server] [type] [class] [domain]
Options:
  -p <num>  server port number (default: 53, 853 for +tls)
  -y <tsig> use TSIG key (default: none, example: "testkey:hmac-md5:Wg==")
  -x <ip>   do a reverse lookup
  -f json   return DNS response as JSON
  +tcp      use TCP for transport
  +tls      use TLS for transport
  +short    print only answer records
  +cd       DNSSEC checking disabled
  +do       request DNSSEC records
  +cookie   request DNS cookie
  +cookie=x pass DNS cookie
Examples:
  ldig	-x 192.168.1.1
  ldig	NS cz +do
  ldig	@2001:678:f::1 AAAA nic.cz +tcp
  ldig	-y xfrkey:hmac-md5:Wg== @127.0.0.1 -p 5353 AXFR nic.cz
```

dig(1) clone
------------

Supports most widely used parameters and options of ISC DiG, nothing fancy but useful
for quick diagnostics.

```bash
# Get the basics done
$ ldig NS example.com +dnssec
$ ldig -x ::1 +bufsize=1280
# Get the DNS/TLS done too
$ ldig @185.49.141.38 +tls
```

Apart from the compatibility format, `ldig` is able to return response in JSON as defined in [Google's DNS-over-HTTPS](https://developers.google.com/speed/public-dns/docs/dns-over-https).

```bash
$ ldig -f json TXT cz | jq
{
  "Status": 0,
  "TC": false,
  "RD": true,
  "RA": true,
  "AD": false,
  "CD": false,
  "Question": [
    {
      "name": "cz.",
      "type": 16
    }
  ],
  "Authority": [
    {
      "name": "cz.",
      "type": 6,
      "TTL": 900,
      "data": "a.ns.nic.cz. hostmaster.nic.cz. 1469776062 900 300 604800 900"
    }
  ]
}
```

zq - a jq for zone files
------------------------

Or also a strange misfit similar to grep(1) and awk(1) specialized for RFC1035 zone files.
This is a tool built on DNS library [zone sifting](../README.md).
It can parse a zone file, apply filters and transform them.

This is handy for various use cases:

```bash
# Prettify zone file and sort it canonically
$ zq -s example.com.zone

# Parse zone and transform it into JSON
$ zq -f json example.com.zone

# Filter-out NSEC records
$ zq type~=SOA example.com.zone
```

Another usage of the tool is to get DNS answers from a zone file
without starting a daemon or any other DNS software.

```bash
# Extract only SOA from zone and turn it into JSON
# Hint: see "Zone sifting" for introduction into filter rules
$ zq -f json SOA example.com.zone

# Feed it into jq(1) for further transformation
$ zq -f json SOA example.com.zone | jq '.[0].rdata'

# Use it as an offline query tool into zone data
# Query: which domains are hosted by "bighoster.is" ?
$ zq -f json NS(bighoster.is) example.com.zone | jq -r '.[].owner'

# Query for only one RR set (speeds up search)
$ zq -1 -f json 1.nu NS zones/nu.zone | jq .
[
  {
    "name": "1.nu.",
    "type": 2,
    "TTL": 86400,
    "data": "ns1.qu.com."
  },
  {
    "name": "1.nu.",
    "type": 2,
    "TTL": 86400,
    "data": "ns2.qu.com."
  }
]
```

namepile - poor man's zone transfer server
------------------------------------------

This is a simple daemon that provides zone transfers for a pile of zones.
It expects to find files ending with .zone, zones are parsed and streamed on demand,
so it starts up immediately, and doesn't have any significant memory requirements.
It is able to multiplex outgoing streams, so many zones may be transferred in parallel.

```bash
$ mkdir pile
$ echo "$ORIGIN example" > pile/example.zone
$ echo "@ 3600 IN SOA dns hostmaster 0 10800 3600 1209600 60" >> pile/example.zone
$ echo -e "@ 3600 IN NS ns1\nns1 3600 IN A 1.2.3.4" >> pile/example.zone
$ namepile pile @127.0.0.1#4242 &
$ ldig AXFR @127.0.0.1#4242 example.
```
