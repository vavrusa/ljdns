route {
	lru {},
	whoami {},
	file { path = 'zones/example.zone' },
	dnssec { algorithm = 'ecdsa_p256_sha256' },
	rrl { rate = 20 },
}

route('skydns', {
	lru {},
	skydns { zone = 'skydns.local' },
})

route('secondary', {
	secondary { source = 'zones' },
})

route('recursive', {
	cookie {},
	lru {},
	rrl { rate = 20 },
	proxy {
		origins = {'8.8.8.8#53', '8.8.4.4'},
		weights = {10, 20},
		select = 'weighted',
		proto = 'tcp',
		poolsize = 4,
	},
})

listen('tls://127.0.0.1#53537', {
	recursive = {'.'},
},{
	certfile = 'test.crt',
	keyfile = 'test.key'
})

listen('127.0.0.1#53535', {
	default = {
		'example',
	},
	skydns = {
		'skydns.local'
	},
	recursive = {
		'vavrusa.com'
	},
	secondary = {
		'flags', 'nu', 'se', 'example.com'
	}
})