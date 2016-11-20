local ffi = require('ffi')
local nb = require('dns.nbio')
local gnutls = ffi.load('gnutls')
local S = require('syscall')
local c = S.c

-- GnuTLS init flags
local flags = {
    SERVER =  1,
    CLIENT =  2,
    DATAGRAM =  4,
    NONBLOCK =  8,
    NO_EXTENSIONS =  16,
    NO_REPLAY_PROTECTION =  32,
    NO_SIGNAL =  64,
}

-- GnuTLS defaults
local default = {
    HANDSHAKE_TIMEOUT = -1,
}

-- Credentials type
local crd = {
    CERTIFICATE = 1,
    ANON        = 2,
    SRP         = 3,
    PSK         = 4,
    IA          = 5
}

-- X.509 certificate format
local x509_crt_fmt = {
    DER = 0,
    PEM = 1
}

-- X.509 certificate request
local x509_crt_req = {
    IGNORE = 0,
    REQUEST = 1,
    REQUIRE = 2,
}

-- Mapped GnuTLS basic error codes
local err = {
    SUCCESS =  0,
    UNKNOWN_COMPRESSION_ALGORITHM =  -3,
    UNKNOWN_CIPHER_TYPE =  -6,
    LARGE_PACKET =  -7,
    UNSUPPORTED_VERSION_PACKET =  -8,
    UNEXPECTED_PACKET_LENGTH =  -9,
    INVALID_SESSION =  -10,
    FATAL_ALERT_RECEIVED =  -12,
    UNEXPECTED_PACKET =  -15,
    WARNING_ALERT_RECEIVED =  -16,
    ERROR_IN_FINISHED_PACKET =  -18,
    UNEXPECTED_HANDSHAKE_PACKET =  -19,
    UNKNOWN_CIPHER_SUITE =  -21,
    UNWANTED_ALGORITHM =  -22,
    MPI_SCAN_FAILED =  -23,
    DECRYPTION_FAILED =  -24,
    MEMORY_ERROR =  -25,
    DECOMPRESSION_FAILED =  -26,
    COMPRESSION_FAILED =  -27,
    AGAIN =  -28,
    EXPIRED =  -29,
    DB_ERROR =  -30,
}

ffi.cdef [[
typedef void* gnutls_session_t;
typedef void* gnutls_certificate_credentials_t;
typedef void* gnutls_anon_client_credentials_t;
typedef int gnutls_x509_crt_fmt_t;
typedef int gnutls_server_name_type_t;
typedef int gnutls_close_request_t;
typedef int gnutls_credentials_type_t;
typedef int gnutls_certificate_request_t;
typedef struct {
    unsigned char *data;
    unsigned int size;
} gnutls_datum_t;
typedef struct {
    gnutls_session_t session[1];
    int fd;
} tls_session_t;

const char *gnutls_check_version(const char *req_version);
void gnutls_certificate_free_credentials(gnutls_certificate_credentials_t sc);
int gnutls_certificate_allocate_credentials(gnutls_certificate_credentials_t* res);
void gnutls_anon_free_client_credentials(gnutls_anon_client_credentials_t sc);
int gnutls_anon_allocate_client_credentials(gnutls_anon_client_credentials_t* sc);
int gnutls_certificate_set_x509_trust_file(gnutls_certificate_credentials_t cred, const char *cafile, gnutls_x509_crt_fmt_t type);
int gnutls_certificate_set_x509_key_file(gnutls_certificate_credentials_t res, const char *certfile, const char *keyfile, gnutls_x509_crt_fmt_t type);
int gnutls_init(gnutls_session_t * session, unsigned int flags);
void gnutls_deinit(gnutls_session_t session);
void gnutls_session_set_ptr(gnutls_session_t session, void *ptr);
void *gnutls_session_get_ptr(gnutls_session_t session);
int gnutls_server_name_set(gnutls_session_t session, gnutls_server_name_type_t type, const void *name, size_t name_length);
int gnutls_set_default_priority(gnutls_session_t session);
int gnutls_credentials_set(gnutls_session_t session, gnutls_credentials_type_t type, void *cred);
int gnutls_credentials_get(gnutls_session_t session, gnutls_credentials_type_t type, void **cred);                           
void gnutls_session_set_verify_cert(gnutls_session_t session, const char *hostname, unsigned flags);
void gnutls_transport_set_int2(gnutls_session_t session, int r, int s);
void gnutls_handshake_set_timeout(gnutls_session_t session, unsigned int ms);
int gnutls_handshake(gnutls_session_t session);
int gnutls_bye(gnutls_session_t session, gnutls_close_request_t how);
int gnutls_error_is_fatal(int error);
const char *gnutls_strerror(int error);
char *gnutls_session_get_desc(gnutls_session_t session);
ssize_t gnutls_record_send(gnutls_session_t session, const void *data, size_t data_size);
ssize_t gnutls_record_recv(gnutls_session_t session, void *data, size_t data_size);
int gnutls_priority_set_direct(gnutls_session_t session, const char *priorities, const char **err_pos);
void gnutls_certificate_server_set_request(gnutls_session_t session, gnutls_certificate_request_t req);
int gnutls_certificate_set_x509_system_trust(gnutls_certificate_credentials_t cred);
]]

ffi.metatype('tls_session_t', {
    __gc = function (self)
        self:close()
    end,
    __index = {
        send = function (self, msg, len)
            local ret = gnutls.gnutls_record_send(self.session[0], msg, len or #msg)
            while ret == err.AGAIN do
                coroutine.yield(nb.writers, self.fd)
                ret = gnutls.gnutls_record_send(self.session[0], msg, len or #msg)
            end
            if ret < 0 then return nil, {errno=c.E.IO, strerr=gnutls.gnutls_strerror(ret)} end
            return ret
        end,
        receive = function (self, buflen, buf)
            buflen = buflen or 512
            -- Allocate buffer for receiving
            local copy
            if buf then
                buf = ffi.cast('char *', buf)
            else
                buf = ffi.new('char [?]', buflen)
                copy = true
            end
            -- Receive record or wait until ready
            local ret = gnutls.gnutls_record_recv(self.session[0], buf, buflen)
            while ret == err.AGAIN do
                coroutine.yield(nb.readers, self.fd)
                ret = gnutls.gnutls_record_recv(self.session[0], buf, buflen)
            end
            if ret < 0 then return nil, {errno=c.E.IO, strerr=gnutls.gnutls_strerror(ret)} end
            -- If we allocated buffer, return immutable copy
            if copy then
                return ffi.string(buf, ret)
            end
            return ret
        end,
        getpeername = function (self)
            return S.getpeername(self.fd)
        end,
        close = function (self)
            if self.fd < 0 then return end
            gnutls.gnutls_deinit(self.session[0])
            S.close(self.fd)
            self.fd = -1
        end,
    }
})

-- Check GnuTLS version before initializing
if gnutls.gnutls_check_version('3.3.0') == nil then
    error('GnuTLS 3.3.0 or later is required')
end

local creds = {open = {}}

-- Create anonymous credentials
creds.anon = ffi.new('struct { gnutls_anon_client_credentials_t data[1]; }')
gnutls.gnutls_anon_allocate_client_credentials(creds.anon.data)
ffi.gc(creds.anon, function (p) gnutls.gnutls_anon_free_client_credentials(p.data[0]) end)

-- Create X.509 system credentials (if available)
function creds.x509(tbl)
    local cred = ffi.new('struct { gnutls_certificate_credentials_t data[1]; }')
    gnutls.gnutls_certificate_allocate_credentials(cred.data)
    ffi.gc(cred, function (p) gnutls.gnutls_certificate_free_credentials(p.data[0]) end)
    -- Set trust file (PEM format)
    local ret
    if tbl.cafile then
        ret = gnutls.gnutls_certificate_set_x509_trust_file(cred.data[0], tbl.cafile, x509_crt_fmt.PEM)
    else
        ret = gnutls.gnutls_certificate_set_x509_system_trust(cred.data[0])
    end
    if ret < 0 then return nil, ffi.string(gnutls.gnutls_strerror(ret)) end
    -- Set client certificate (if provided)
    if tbl.keyfile and tbl.certfile then
        ret = gnutls.gnutls_certificate_set_x509_key_file(cred.data[0], tbl.certfile, tbl.keyfile, x509_crt_fmt.PEM)
        if ret < 0 then return nil, ffi.string(gnutls.gnutls_strerror(ret)) end
    end
    table.insert(creds.open, cred)
    return cred
end

-- Open default X.509 creds from system default CA file, we're NOT doing peer verification
creds.client_x509 = creds.x509 {}

-- Module interface
local M = {
    creds = creds,
}

-- Perform TLS handshake
local function handshake(s)
    gnutls.gnutls_transport_set_int2(s.session[0], s.fd, s.fd)
    gnutls.gnutls_handshake_set_timeout(s.session[0], default.HANDSHAKE_TIMEOUT)
    local ret = gnutls.gnutls_handshake(s.session[0])
    while ret < 0 and gnutls.gnutls_error_is_fatal(ret) == 0 do
        if ret == err.AGAIN then coroutine.yield(nil, s.fd) end
        ret = gnutls.gnutls_handshake(s.session[0])
    end
    if ret < 0 then
        return nil, ffi.string(gnutls.gnutls_strerror(ret))
    end
    return true
end

-- Create TLS session
-- https://www.gnutls.org/manual/html_node/Simple-client-example-with-X_002e509-certificate-support.html#Simple-client-example-with-X_002e509-certificate-support
local function session(sock, flag, cred)
    local s = ffi.new('tls_session_t', {nil}, sock.fd)
    -- Initialize TLS session
    gnutls.gnutls_init(s.session, flag + flags.NONBLOCK)
    local ret = gnutls.gnutls_set_default_priority(s.session[0])
    if ret < 0 then return nil, ffi.string(gnutls.gnutls_strerror(ret)) end
    ret = gnutls.gnutls_priority_set_direct(s.session[0], 'NORMAL', nil)
    if ret < 0 then return nil, ffi.string(gnutls.gnutls_strerror(ret)) end
    -- Set X.509 credentials (if provided)
    if cred then
        ret = gnutls.gnutls_credentials_set(s.session[0], crd.CERTIFICATE, cred.data[0])
    else
        ret = gnutls.gnutls_credentials_set(s.session[0], crd.ANON, creds.anon.data[0])
    end
    if ret < 0 then return nil, ffi.string(gnutls.gnutls_strerror(ret)) end
    return s
end

-- Create TLS client from connected socket
function M.client(sock, cred)
    if cred == 'x509' then cred = creds.client_x509 end
    local ok, err = session(sock, flags.CLIENT, cred)
    if not ok then return nil, err end
    local session = ok
    ok, err = handshake(session)
    if not ok then return nil, err end
    return session
end

-- Create TLS server from connected socket
function M.server(sock, cred, key)
    -- Create session
    local ok, err = session(sock, flags.SERVER, cred)
    if not ok then return nil, err end
    local session = ok
    -- Don't request certificate from a client
    gnutls.gnutls_certificate_server_set_request(session.session[0], x509_crt_req.IGNORE)
    -- Perform handshake and return
    ok, err = handshake(session)
    if not ok then return nil, err end
    return session
end

return M