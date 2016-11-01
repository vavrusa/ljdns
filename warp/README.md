# Warp

Warp is a DNS router that chains various DNS services together. It allows you to build server combining load-balancer, proxy and authoritative server in one package. Or caching recursive server. Or an edge-side DNS filter. It runs either stand-alone, or atop NGINX / [OpenResty][openresty] to leverage its non-blocking I/O, good performance, and familiarity with its operations.

Unlike pure load balancers, it provides cutting-edge DNS features, such as RFC7873 DNS Cookies, Response Rate Limiting, DNS-over-TLS, TCP pipelining, out-of-order processing, and long-lived connections for proxying. It also allows running performance-critical application logic directly on edge, to e.g. serve "hot" zones directly, and proxy others.

Unlike middleware servers, it has good performance and advanced load-balancing features (traffic shaping, RTT tracking, weighted origin pools, shunting of abuse traffic).

Warp is somewhere in between - able to replace either of those, or supercharge an existing DNS infrastructure with modern DNS features and filtering.

## Quick start

Let's start with a "hello world" that introduces two constructs - `route` and `listen`.
It's fully functional DNS application that serves DNS queries and generates an answer.

```lua
$ cat << EOF > hello.lua
route {
	function () return '\5world', 60 end
}
listen '127.0.0.1#53535'
EOF
```
```bash
$ warp hello.lua &
$ dig @127.0.0.1 -p 53535 +short hello TXT
"world"
```

The `route` statement defines a function chain to be executed, and `listen` address and port pairs. Route steps can be chained, let's add DNS COOKIE support.

```lua
$ cat << EOF > hello.lua
route {
	cookie {},
	function () return '\5world', 60 end
}
listen '127.0.0.1#53535'
EOF
```
```bash
$ warp hello.lua &
$ ldig @127.0.0.1 -p 53535 +cookie hello TXT
; EDNS: version: 0, flags:; udp: 4096; cookie: 8486A77DF092372A83ECF56F71A7F50B
hello.              	60	TXT	"world"
```

The routes can be chained too if you name them. Route steps can terminate the filter chain,
this allows you to create sparse views.

```lua
$ cat << EOF > hello.lua
route('ratelimiter', {
	rrl { rate = 20 }
})
route {
	cookie {},
	whoami { zone = 'hello' },
	function (req)
		if req.answer:empty() then
			return '\5world', 60
		end
	end,
	routes.ratelimiter,
}
listen '127.0.0.1#53535'
EOF
```
```bash
$ warp hello.lua &
$ dig @127.0.0.1 -p 53535 +short hello TXT
"world"
$ dig @127.0.0.1 -p 53535 +short whoami.hello TXT
"127.0.0.1"
```

Different zones may be serviced using different routes. This allows you to create different views of the zone tree.

```lua
$ cat << EOF > hello.lua
route('proxy', {
	proxy { origins = { '8.8.8.8', '8.8.4.4' } }
})
route('hello', {
	function () return '\5world', 60 end,
})
listen('127.0.0.1#53535', {
	hello = { 'local' },
	proxy = { '.' },
})
EOF
```
```bash
$ warp hello.lua &
$ dig @127.0.0.1 -p 53535 +short hello.local TXT
"world"
$ dig @127.0.0.1 -p 53535 +short cloudflare.com SOA
cloudflare.com. 21530 SOA ns3.cloudflare.com. dns.cloudflare.com. 2022875358 10000 2400 604800 300
```

## Installation

```bash
$ luarocks install warp
```

### Requirements

- [ljdns][ljdns] - the LuaJIT DNS library.

### Running stand-alone

```bash
$ warp config.lua
```

### Running in OpenResty

See [openresty/stream-lua-nginx-module][stream-lua].

## Example

Here's an example of a more complicated routing definition.

```lua
-- Route to load-balancing proxy with cookies
route {
	cookie {},
	lru {},
	proxy {
		origins = {'8.8.8.8#53', '8.8.4.4'},
		weights = {10, 20},
		select = 'weighted',
		proto = 'tcp',
		poolsize = 4,
		rate = 1000,
	},
	rrl { rate = 5 },
}
-- Route to serve local zone with online signing
route('static', {
	lru {},
	whoami {},
	auth { source = 'zones' },
	dnssec { algorithm = 'ecdsa_p256_sha256' },
	rrl { rate = 20 },
})
-- Listen on both UDP and TCP
listen('127.0.0.1#53535', {
	default = {'.'}, -- Proxy all zones
	static = { 'port53.rocks' }, -- Serve at the edge
})
-- DNS/TLS tunnel to proxy
listen('tls://127.0.0.1#53537', {
	default = {'.'},
},{
	certfile = 'test.crt',
	keyfile = 'test.key'
})
```

## Status

ACME

## Routes

Similarly to [CoreDNS][coredns], it allows you to write middleware without worrying about the logistics. You can create routes like this:

```lua
route {
	lru {},
	auth { source = 'zones' }, 
	dnssec {},
}
```

There are several built-in routes:

* route/dnssec - online DNSSEC signer with support for *"black lies"*, automatic key management
* route/file - stream answers from zone files on disk
* route/lru - a LRU cache of answers
* route/prometheus - an interface to serve metrics to Prometheus scrapers
* route/rrl - response rate limiting
* route/skydns - a distributed service discovery and announcement with DNS ([SkyDNS][skydns] replacement)
* route/whoami - service that responds with query source in given zones
* route/cookie - implements [RFC7873][rfc-cookies] DNS cookies
* route/auth - DNS secondary service syncing to backing store (zone files or primary)

You can write your own routes with inline closures:

```lua
local zone = dns.dname.parse('example')
route {
	function (req)
		if req.qname:within(zone) then
			return '\4yes!'
		end
	end
}
```

Or write complete routes with `serve` and `complete` interface.

## Examples

TBD

[openresty]: http://openresty.org
[coredns]: https://github.com/miekg/coredns
[dnsdist]: https://dnsdist.org
[skydns]: https://github.com/skynetservices/skydns#service-announcements
[stream-lua]: https://github.com/vavrusa/stream-lua-nginx-module/blob/bloody-dns-server/lua/dns_server.lua
[rfc-cookies]: https://tools.ietf.org/html/rfc7873
[ljdns]: https://github.com/vavrusa/ljdns
