package = "luajit-kdns"
version = "0.1-1"
source = {
   url = "git://github.com/vavrusa/luajit-kdns"
}
description = {
   summary = "A contemporary DNS library focused on performance using LuaJIT FFI.",
   detailed = [[
   ]],
   homepage = "https://github.com/vavrusa/luajit-kdns",
   license = "BSD"
}
dependencies = {
   "lua >= 5.1",
   "ljsyscall >= 0.11",
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
      zonepile = "examples/zonepile.lua"
    }
  },
  modules = {
    ["kdns.io"] = "kdns/io.lua",
    ["kdns.rrparser"] = "kdns/rrparser.lua",
    ["kdns.sift"] = "kdns/sift.lua",
    ["kdns.utils"] = "kdns/utils.lua",
    kdns = "kdns.lua",
    kdns_clib = "src/utils.c",
  }
}
