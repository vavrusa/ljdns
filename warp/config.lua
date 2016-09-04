route {
	lru {},
	whoami {},
	file {
		path = 'zones'
	},
	dnssec {
		algorithm = 'ecdsa_p256_sha256',
	}
}