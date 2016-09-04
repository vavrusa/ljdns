local M = {}

-- Cache replaced global symbols
local require = _G.require

-- Resty Core compatibility
local log = {ERR = 'error', NOTICE = 'notice', INFO = 'info', DEBUG = 'debug'}
local ngx = {
	now = require('dns.nbio').now,
	say = print,
	log = function (l, msg, ...)
		if l == log.DEBUG then return end
		return print('[resty]', l, msg, ...)
	end,
	config = {ngx_lua_version = 10008},
	null = require('ffi').null,
	socket = {},
	req = {},
	re = {},
	-- Log levels
}
for k,v in pairs(log) do ngx[k] = v end

-- Module environment
local env = {
	ngx = ngx,
}

local function loadpkg(pkg, env)
	local m = package.loaded[pkg]
	if not m then
		-- Load the vendored module
		m = package.loaders[2](pkg)
		if type(m) == 'function' then
			-- Set environment and load
			setfenv(m, env) m = m()
		end
		package.loaded[pkg] = m
	end
	return m
end

-- Override require function to load vendored resty modules
local pkgfmt = 'warp.vendor.lua-resty-%s.lib.resty.%s'
env.require = function (pkg, env)
	local resty, name = pkg:match '(resty).(%S+)'
	if resty then
		-- Load Resty module
		local m = loadpkg(pkgfmt:format(name, name), env)
		if type(m) ~= 'table' then
			-- Load submodule if not exists
			env = getfenv(2) -- Get module env
			m = loadpkg(pkgfmt:format(env.modname, name), env)
		end
		return m
	end
	return require(pkg)
end

local ffi, S, nbio = require('ffi'), require('syscall'), require('dns.nbio')

-- Metatable for streams
local tcp_t = {
	getfd = function (s) return s.fd end,
	send = function (s, buf, len)
		assert(s.fd, 'not connected socket')
		if type(buf) == 'table' then buf = table.concat(buf, '') end
		return nbio.nbsend(s.fd, buf)
	end,
	receive = function (s, len)
		assert(s.fd, 'not connected socket')
		-- Default is read line filter
		if len == '*l' then len = nil end
		local wanted
		-- Read more if necessary
		if s.buf then
			if len then
				wanted, len = len, math.max(len - #s.buf, 0)
			else
				wanted, len = s.buf:find('\n', 1, true), 0
			end
		end
		local rlen, buf = nbio.nbrecv(s.fd, nil, len)
		if len ~= rlen and rlen == 0 then
			return nil, buf
		end
		-- Concat with buffered data
		if rlen > 0 then
			buf = ffi.string(buf, rlen)
			if s.buf then
				rlen = rlen + #s.buf
				buf = s.buf .. buf
			end
		else
			buf, rlen = s.buf, #s.buf
		end
		s.buf = nil
		-- OpenResty defaults to getline() filter
		if not len then
			local nl = buf:find('\n', 1, true)
			if not nl then
				s.buf = buf -- Keep buffering
			else
				if nl < rlen then
					s.buf = buf:sub(nl + 1)
				end
				if buf:byte(nl - 1) == string.byte('\r') then
					nl = nl - 1 -- Trim \r
				end
				buf = buf:sub(1, nl)
			end
		else
			if rlen > wanted then
				s.buf = buf:sub(wanted + 1)
				buf = buf:sub(1, wanted)
			end
		end
		return buf
	end,
	connect = function (s, host, port)
		assert(not s.fd, 'already connected socket')
		local addr = nbio.addr(host, port)
		s.fd = nbio.socket(addr, true, true)
		return nbio.connect(s.fd, addr)
	end,
	settimeout = function (s, t) s.timeout = t end,
	setkeepalive = function (s, t) print('NYI: ngx.socket.tcp.setkeepalive') return true end,
}

-- Compatibility for nbio
function ngx.socket.tcp()
	return setmetatable({}, {__index=tcp_t})
end

-- NGINX request API
ngx.req.socket = ngx.socket.tcp
function ngx.req.get_headers(...)
	error(...)
end
function ngx.req.get_method(...)
	error(...)
end

-- NGINX regex API
local has_rex, rex = pcall(require, 'rex_pcre')
if not has_rex then rex = {} end
function ngx.re.match(subj, patt, cf)
	return {rex.match(subj, patt, nil, cf)}
end
function ngx.re.gsub(subj, patt, replace, cf)
	return rex.gsub(subj, patt, replace, nil, cf)
end

-- Connector to jail environment
M.env = env

-- Load compatibility module
function M.require(pkg, modenv)
	-- Update environment
	modenv = setmetatable(modenv or {}, {
		__index = function (t, k) return rawget(t, k) or env[k] or _G[k] end
	})
	modenv.modname = pkg:match 'resty.(%S+)'
	return env.require(pkg, modenv)
end

return M