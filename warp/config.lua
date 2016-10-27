route {
	lru {},
	whoami {},
	file { path = 'zones/example.zone' },
	dnssec { algorithm = 'ecdsa_p256_sha256' },
	rrl { rate = 20 },
	prometheus {},
}

route('skydns', {
	lru {},
	skydns { zone = 'skydns.local' },
})

route('edge', {
	auth { source = 'zones' },
})

route('recursive', {
	cookie {},
	lru {},
	proxy {
		origins = {'8.8.8.8#53', '8.8.4.4'},
		weights = {10, 20},
		select = 'weighted',
		proto = 'tcp',
		poolsize = 4,
	},
	rrl { rate = 20 },
})

route('proxy', {
	cookie {},
	lru {},
	proxy {
		rate = 20,
		origins = {'95.85.40.151', '2a03:b0c0:0:1010::c6:b001'},
		proto = 'tcp',
	},
	rrl { rate = 20 },
})

listen('tls://127.0.0.1#53537', {
	recursive = {'.'},
},{
	certfile = 'test.crt',
	keyfile = 'test.key'
})

listen('127.0.0.1#53535', {
	-- default = {
	-- 	'example',
	-- },
	skydns = {
		'skydns.local'
	},
	recursive = {
		'vavrusa.com'
	},
	edge = {
		'flags', 'nu', 'se', 'example'
	},
	proxy = {
		'udp53.rocks'
	}
})

listen('http://127.0.0.1#8080', {
	['edge.api'] = '/edge',
	['default.api'] = '/api',
})
