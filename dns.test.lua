local dns = require('dns')

-- Test domain names
local dname = dns.dname('\7example\3com')
assert(dname ~= nil)
assert(tostring(dname) == 'example.com.')
dname = dns.dname.parse('example.COM')
assert(dname == '\7example\3COM')
assert(dname:labels() == 2)
assert(dname:lower() == '\7example\3com')
assert(dname:within('\3COM') == true)
assert(dname:within('\2cz') == false)
collectgarbage()
print('[ OK ] dns.dname')

-- Test RDATA
assert(dns.rdata.parse('A') == nil)
assert(dns.rdata.parse('A asdf') == nil)
assert(dns.rdata.parse('NS test') == '\4test\0')
local rd = dns.rdata.a('1.2.3.4')
assert(rd == '\1\2\3\4')
assert(#rd == 4)
assert(dns.rdata.mx('10 test') == '\0\10\4test\0')
assert(dns.rdata.txt('abcd') == '\4abcd')
assert(dns.rdata.parse('LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m') ~= nil)
dns.rdata.parse('SRV 0 5 zzzz')
collectgarbage()
print('[ OK ] dns.rdata')

-- Test RR sets
local rrset = dns.rrset('\3com', dns.type.NS)
collectgarbage()
assert(rrset ~= nil)
assert(rrset:owner() == '\3com')
assert(rrset:class() == dns.class.IN)
assert(rrset:type()  == dns.type.NS)
assert(rrset:count() == 0)
rrset:add(dns.rdata.ns('test'), 3600)
assert(rrset:count() == 1)
assert(rrset:rdata(0) == '\4test\0')
collectgarbage()
local rrset_copy = rrset:copy()
assert(rrset_copy ~= nil)
assert(rrset_copy:owner() == rrset:owner())
assert(dns.dname.equals(rrset_copy:owner(), rrset:owner()))
assert(rrset_copy:count() == rrset:count())
rrset_copy = nil
collectgarbage()
local empty_rrset = dns.rrset(nil, 0)
assert(empty_rrset:owner().bytes == nil)
empty_rrset = nil
collectgarbage()
print('[ OK ] dns.rrset')

-- Test OPT RR
local opt = dns.edns.rrset(0, 4096)
assert(opt ~= nil)
assert(dns.edns.version(opt) == 0)
assert(dns.edns.payload(opt) == 4096)
assert(dns.edns.dobit(opt) == false)
assert(dns.edns.dobit(opt, true) == true)
assert(dns.edns.has(opt, 0x05) == false)
assert(dns.edns.option(opt, 0x05, 'rawraw') == true)
assert(dns.edns.option(opt, 0x05) == 'rawraw')
collectgarbage()
print('[ OK ] dns.edns')

-- Test packet writing
local pkt = dns.packet(512)
assert(pkt ~= nil)
assert(pkt:opcode() == 0)
assert(pkt:rd(true) == true)
assert(pkt:tc(true) == true)
assert(pkt:aa() == false)
assert(pkt:qr(false) == false)
assert(pkt:cd(true) == true)
assert(pkt:ad(true) == true)
assert(pkt:ra() == false)
assert(pkt:id(1234) == 1234)
assert(pkt:question('\4test', dns.type.SOA))
assert(pkt:begin(dns.section.ANSWER))
assert(pkt:put(rrset) == true)
rrset = nil
collectgarbage() -- Must keep reference to RR
assert(pkt:begin(dns.section.ADDITIONAL) == 0)
assert(pkt:put(dns.rrset('\3com', dns.type.A):add(dns.rdata.a('1.2.3.4'), 3600)) == true)
assert(pkt:put(opt) == true)
edns = nil
collectgarbage() -- Must keep reference to RR
assert(pcall(function() pkt:begin(dns.section.ANSWER) end) == false)
print(pkt)
local wire = pkt:towire()
dns.hexdump(wire)
collectgarbage() -- Must keep reference to RR
print('[ OK ] dns.packet.write')

-- Test packet reading
local copy = dns.packet(#wire, wire)
collectgarbage()
assert(copy ~= nil)
assert(copy:parse() == true)
collectgarbage()
assert(copy:id() == pkt:id())
assert(copy:qname() == pkt:qname())
assert(copy:qtype() == pkt:qtype())
assert(copy:qclass() == pkt:qclass())
assert(copy:answers(pkt) == false)
assert(copy:tostring() == pkt:tostring())
copy:qr(true)
assert(copy:answers(pkt) == true)
collectgarbage()
print('[ OK ] dns.packet.copy')

-- Test packet copy
copy = pkt:copy()
collectgarbage() -- Must collect previous copy
assert(copy ~= pkt)
assert(tostring(copy) == tostring(pkt))
copy = nil
collectgarbage()
print('[ OK ] dns.packet.read')

-- Test making answer
copy = dns.packet(#wire)
assert(pkt:toanswer(copy))
assert(copy:qr() == true)
assert(copy:answers(pkt) == true)
copy = nil
collectgarbage()
print('[ OK ] dns.packet.answer')

-- Test TSIG signing
pkt:qr(false)
assert(dns.tsig('bad-') == nil)
local tsig_alice = dns.tsig('testkey:Wg==')
local tsig_bob = dns.tsig('testkey:Wg==')
local tsig_badkey = dns.tsig('badkey:Wg==')
local tsig_badsig = dns.tsig('testkey:YQo=')
assert(tsig_alice ~= nil)
assert(tsig_bob ~= nil)
assert(tsig_alice:sign(pkt))
collectgarbage()
print('[ OK ] dns.tsig.sign')
copy = pkt:copy()
assert(tsig_bob:verify(copy) == true)
assert(tsig_badkey:verify(copy) == dns.rcode_tsig.BADKEY)
assert(tsig_badsig:verify(copy) == dns.rcode_tsig.BADSIG)
print('[ OK ] dns.tsig.verify')
copy:qr(true) -- Make it a response
assert(tsig_bob:sign(copy))
assert(tsig_alice:verify(copy) == true)
collectgarbage()
print('[ OK ] dns.tsig.exchange')
tsig_bob = nil
tsig_alice = nil
collectgarbage()
copy = nil
pkt = nil
collectgarbage()
print('[ OK ] dns.tsig')

-- Test RR parser
local rrparser = require('dns.rrparser')
local fname = 'examples/example.com.zone'
local records = rrparser.file(fname)
assert(records ~= nil)
assert(#records == 10)
print('[ OK ] dns.rrparser.file')
-- Parse input text
local parser = rrparser.new()
assert(parser:parse("foo. IN 3600 NS bar.\n"))
assert(parser.state == rrparser.state.DATA)
assert(parser.error.code == 0)
print('[ OK ] dns.rrparser.parse')
-- Parse file stream
local parsed = 0
local parser = rrparser.new()
assert(parser:open(fname))
while parser:parse() do
	parsed = parsed + 1
end
collectgarbage()
assert(parsed == 10)
stream = nil
rr = nil
print('[ OK ] dns.rrparser.stream')
collectgarbage()
-- Test asynchronous I/O
local go = require('dns.nbio')
local server = go.socket(go.addr('127.0.0.1', 0), true)
local ffi = require('ffi')
-- Function sends PING to client, expects PONG back
local writes, reads = 0, 0
assert(go(function ()
	local client = go.accept(server)
	local ret, err = go.tcprecv(client)
	assert(ret == 'PING')
	reads = reads + 1
	ret, err = go.tcpsend(client, 'PONG')
	writes = writes + 1
end))
assert(go(function ()
	local client = go.socket('inet', true)
	-- Attempt TFO
	go.connect(client, server:getsockname(), 'PING')
	local msg, err = go.tcprecv(client)
	assert(msg == 'PONG')
end))
-- Execute both coroutines
assert(go.coroutines == 2)
assert(go.run(1))
-- Evaluate results
assert(writes == 1)
assert(reads == 1)
-- Must be finished by now
assert(go.coroutines == 0)

-- Test LMDB interface
local S = require('syscall')
local lmdb = require('dns.lmdb')
local tmpdir = string.format('.tmpdb%d', os.time())
if S.stat(tmpdir) then
	S.util.rm(tmpdir)
end
S.mkdir(tmpdir, '0755')
-- Test environment and opening DB handle
local env = assert(lmdb.open(tmpdir, 'writemap', 512*1024))
local txn, db = assert(env:open())
-- Test key set/retrieval
assert(txn:get('test') == nil, 'lmdb: get non-existent')
assert(txn:put('test', 'val'), 'lmdb: put')
assert(not txn:put('test', 'lav', 'nooverwrite'), 'lmdb: put duplicate key')
assert(tostring(txn:get('test')) == 'val', 'lmdb: get')
assert(txn:commit())
-- Test reopen
txn = assert(env:txn(db, 'rdonly'))
assert(not txn:put('test', 'invalid'), 'lmdb: put in read-only txn')
assert(tostring(txn:get('test')) == 'val', 'lmdb: get')
txn:abort()
txn = assert(env:txn(db))
-- Test low-level key/value API
local key = lmdb.val_t(4, 'abcd')
local val = lmdb.val_t(4, 'efgh')
assert(txn:put(key, val), 'lmdb: put #2')
local has = lmdb.val_t()
assert(txn:get(key, has), 'lmdb: get #2')
assert(val.size == has.size, 'lmdb: cmp len')
assert(tostring(val) == tostring(has), 'lmdb: cmp value')
-- Iterate over keys
local cur = txn:cursor()
for i,v in ipairs(cur) do
	assert(i and v)
end
cur:close()
-- Cleanup
txn:abort()
S.util.rm(tmpdir)
print('[ OK ] dns.lmdb')

-- Test TLS
local go = require('dns.nbio')
local server = go.socket(go.addr('127.0.0.1', 0), true)
local tls = require('dns.tls')
-- Function sends PING to client, expects PONG back
local writes, reads = 0, 0
assert(go(function ()
	local client = go.accept(server)
	-- Upgrade to TLS
	client = assert(tls.server(client, tls.creds.x509 {
		certfile = 'test.crt',
		keyfile = 'test.key',
	}))
	local ret, err = go.tcprecv(client)
	assert(ret == 'PING')
	reads = reads + 1
	ret, err = go.tcpsend(client, 'PONG')
	writes = writes + 1
end))
assert(go(function ()
	local client = go.socket('inet', true)
	go.connect(client, server:getsockname())
	-- Upgrade to TLS
	client = assert(tls.client(client, 'x509'))
	go.tcpsend(client, 'PING')
	local msg, err = go.tcprecv(client)
	assert(msg == 'PONG')
end))
-- Execute both coroutines
assert(go.coroutines == 2)
assert(go.run(1))
-- Evaluate results
assert(writes == 1)
assert(reads == 1)
-- Must be finished by now
assert(go.coroutines == 0)

print('[ OK ] dns')
