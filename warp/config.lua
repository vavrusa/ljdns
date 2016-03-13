downstream {
	['127.0.0.1#6668'] = proto.tls {
		certfile = 'dns.crt',
		keyfile  = 'dns.key',
	},
}

upstream {
	['recursive'] = route.dns {
		address = {'8.8.8.8', '8.8.4.4'},
		capabilities = '+edns0 +dnssec',
	},
	['secure'] = route.dns {
		address = {'185.49.141.38'},
		capabilities = '+tls +keepalive',
	},
	['http'] = route.dns {
		address = {'1.2.3.4'},
		cafile = 'remote.crt',
	},
	['localzone'] = route.file {
		path = 'pile',
	},
	['lru'] = route.cache {
		backend = 'lmdb',
		path = '/tmp/cache',
	}
}

routes {
	['test'] = {'lru', 'localzone'},
	['com'] = {'lru', 'localzone', 'recursive'},
	['.'] = {'lru', 'recursive'}
}