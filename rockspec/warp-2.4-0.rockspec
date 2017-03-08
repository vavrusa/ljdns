package = "warp"
version = "2.4-0"
source = {
   url = "git://github.com/vavrusa/ljdns",
   tag = "v2.4-0"
}
description = {
   summary = "A DNS router/middleware server that can run in OpenResty.",
   detailed = [[
	This is a DNS router that can either run standalone or inside OpenResty and routes requests through middlwares.
        It supports zonefile-based backend, full DNSSEC with KASP, DNS/TLS, proxying, LRU caches, etcd-based SkyDNS any others.
   ]],
   homepage = "https://github.com/vavrusa/ljdns",
   license = "BSD"
}
dependencies = {
   "ljdns >= 2.4",
}
build = {
  type = "builtin",
  install = {
    bin = {
      warp = "warp/warp.lua"
    }
  },
  modules = {
    ["warp.init"] = "warp/init.lua",
    ["warp.route"] = "warp/route.lua",
    ["warp.route.cookie"] = "warp/route/cookie.lua",
    ["warp.route.dnssec"] = "warp/route/dnssec.lua",
    ["warp.route.file"] = "warp/route/file.lua",
    ["warp.route.lru"] = "warp/route/lru.lua",
    ["warp.route.prometheus"] = "warp/route/prometheus.lua",
    ["warp.route.proxy"] = "warp/route/proxy.lua",
    ["warp.route.rrl"] = "warp/route/rrl.lua",
    ["warp.route.auth"] = "warp/route/auth.lua",
    ["warp.route.skydns"] = "warp/route/skydns.lua",
    ["warp.route.whoami"] = "warp/route/whoami.lua",
    ["warp.store.etcd"] = "warp/store/etcd.lua",
    ["warp.store.lmdb"] = "warp/store/lmdb.lua",
    ["warp.store.redis"] = "warp/store/redis.lua",
    ["warp.vendor.resty"] = "warp/vendor/resty.lua",
    warp = "warp/init.lua",
    -- Vendored modules
    ["warp.vendor.lua-resty-http.lib.resty.http"] = "warp/vendor/lua-resty-http/lib/resty/http.lua",
    ["warp.vendor.lua-resty-http.lib.resty.http_headers"] = "warp/vendor/lua-resty-http/lib/resty/http_headers.lua",
    ["warp.vendor.lua-resty-lrucache.lib.resty.lrucache"] = "warp/vendor/lua-resty-lrucache/lib/resty/lrucache.lua",
    ["warp.vendor.lua-resty-redis.lib.resty.redis"] = "warp/vendor/lua-resty-redis/lib/resty/redis.lua",
    
  }
}
rockspec_format = "1.1"
deploy = { wrap_bin_scripts = false }
