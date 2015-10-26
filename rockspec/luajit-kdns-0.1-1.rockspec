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
   "lua >= 5.1", -- "luajit >= 2.0.0"
}
external_dependencies = {
    LIBZSCANNER = {
       library = "zscanner"
    }
    LIBKNOT = {
       library = "knot"
    }
 }
build = {
  type = "make"
}
