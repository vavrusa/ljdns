# Warp

Warp is a DNS router that chains various DNS services together. It allows you to build server combining load-balancer, proxy and authoritative server in one package. Or caching recursive server. Or an edge-side DNS filter. It runs either in NGINX [OpenResty][openresty] or stand-alone.

Instead of building another application server, Warp can live on top of existing server - such as NGINX, and leverage its nonblocking I/O, good performance, and operational familiarity.

Unlike load balancers, it also provides cutting-edge DNS features, such as RFC7873 DNS Cookies, Response Rate Limiting, DNS-over-TLS, TCP pipelining, out-of-order processing, and long-lived connections for proxying. It also allows running performance-critical application logic directly on edge, to e.g. serve "hot" zones directly, and proxy others.

Unlike middleware servers, it has good performance and advanced load-balancing features (traffic shaping, RTT tracking, weighted origin pools, shunting of abuse traffic).

Warp is somewhere in between - it's able to replace either of those, however its purpose is to keep your existing infrastructure in place, and supercharge it.

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

```lua
-- Route to load-balancing proxy with cookies
route {
	cookie {},
	lru {},
	rrl { rate = 5 },
	proxy {
		origins = {'8.8.8.8#53', '8.8.4.4'},
		weights = {10, 20},
		select = 'weighted',
		proto = 'tcp',
		poolsize = 4,
	},
}
-- Route to serve local zone with online signing
route('static', {
	lru {},
	whoami {},
	file { path = 'zones/example.zone' },
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

Similarly to [CoreDNS][coredns], it allows you to write middleware without worrying about the logistics. It's just called "routes", and represents things you can do with the DNS messages.

These routes are available:

* route/dnssec - online DNSSEC signer with support for *"black lies"*, automatic key management.
* route/file - respond from zone files on disk, it parses the zone file for each query so they may be live-edited.
* route/lru - a LRU cache of answers.
* route/prometheus - an interface to serve metrics to Prometheus scrapers.
* route/rrl - response rate limiting.
* route/skydns - a distributed service discovery and announcement with DNS ([SkyDNS][skydns] replacement).
* route/whoami - service that responds with query source in given zones.
* route/cookie - implements [RFC7873][rfc-cookies] DNS cookies
* route/secondary - DNS secondary service syncing to backing store (zone files or primary)

### route/dnssec
### route/file
### route/lru
### route/prometheus
### route/rrl
### route/skydns
### route/whoami
### route/cookie

## Examples

TBD

[openresty]: http://openresty.org
[coredns]: https://github.com/miekg/coredns
[dnsdist]: https://dnsdist.io
[skydns]: https://github.com/skynetservices/skydns#service-announcements
[stream-lua]: https://github.com/vavrusa/stream-lua-nginx-module/blob/bloody-dns-server/lua/dns_server.lua
[rfc-cookies]: https://tools.ietf.org/html/rfc7873