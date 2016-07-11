package = "ljdns"
version = "0.2-1"
source = {
   url = "git://github.com/vavrusa/ljdns"
}
description = {
   summary = "A contemporary DNS library focused on performance using LuaJIT FFI.",
   detailed = [[
	The goal of this project is a fast DNS library for testing new RFCs and building DNS services.
	It supports all widely used DNS records (DNSSEC included) with a lean and mean API, including DNS primitives,
	messages and asynchronous I/O (including coroutines, TCP Fast Open and SO_REUSEPORT), and DNS over TLS.
   ]],
   homepage = "https://github.com/vavrusa/ljdns",
   license = "BSD"
}
dependencies = {
   "lua >= 5.1",
   "ljsyscall >= 0.12",
}
external_dependencies = {
    LIBZSCANNER = {
       library = "zscanner"
    },
    LIBKNOT = {
       library = "knot"
    }
}
build = {
  type = "builtin",
  install = {
    bin = {
      zq = "examples/zq.lua",
      ldig = "examples/dig.lua",
      namepile = "examples/namepile.lua"
    }
  },
  modules = {
    ["kdns.aio"] = "kdns/aio.lua",
    ["kdns.rrparser"] = "kdns/rrparser.lua",
    ["kdns.sift"] = "kdns/sift.lua",
    ["kdns.utils"] = "kdns/utils.lua",
    ["kdns.lmdb"] = "kdns/lmdb.lua",
    ["kdns.tls"] = "kdns/tls.lua",
    kdns = "kdns.lua",
    kdns_clib = "src/utils.c",
  }
}
rockspec_format = "1.1"
deploy = { wrap_bin_scripts = false }
