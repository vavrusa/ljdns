package = "warp"
version = "0.1-1"
source = {
   url = "git://github.com/vavrusa/ljdns"
}
description = {
   summary = "A DNS router/middleware server that can run in OpenResty.",
   detailed = [[
	This is a DNS router that can either run standalone or inside OpenResty and routes requests through middlwares.
        It supports zonefile-based backend, full DNSSEC with KASP, LRU caches, etcd-based SkyDNS any others.
   ]],
   homepage = "https://github.com/vavrusa/ljdns",
   license = "BSD"
}
dependencies = {
   "ljdns >= 0.3",
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
    ["warp.route.dnssec"] = "warp/route/dnssec.lua",
    ["warp.route.etcd"] = "warp/route/etcd.lua",
    ["warp.route.file"] = "warp/route/file.lua",
    ["warp.route.lru"] = "warp/route/lru.lua",
    ["warp.route.lruredis"] = "warp/route/lruredis.lua",
    ["warp.route.whoami"] = "warp/route/whoami.lua",
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
