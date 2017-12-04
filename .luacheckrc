std = 'luajit'
new_read_globals = {
    'bytes',
    'ngx',
    'sample_keys'
}

-- Luacheck < 0.18 doesn't support new_read_globals
new_globals = new_read_globals

ignore = {
    '4.1/err', -- Shadowing err
    '4.1/.',   -- Shadowing one letter variables
}

-- Allow cdefs to be long
files['dns/tls.lua'].ignore = {'631'}
files['dns/dnssec.lua'].ignore = {'631'}
files['dns/cdef.lua'].ignore = {'631'}

-- Allow globals mocks and different env for tests
files['spec/*'] = {
	ignore = {'111', '112', '113', '121', '122', '411'},
	std = "+busted",
}