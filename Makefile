PREFIX ?= /usr/local
LUA ?= luajit
ABIVER ?= 5.1
PREFIX_LMOD ?= $(PREFIX)/share/lua/$(ABIVER)
INSTALL ?= install
CFLAGS ?= -std=c99 -O2 -g -fPIC
LIBEXT := so

# Scripts and extras
OBJS := dns
LIBS := $(addsuffix .lua,$(OBJS))
EXTRA := $(wildcard dns/*)
CLIB := kdns_clib.$(LIBEXT)

# Rules
all: check
check: $(addsuffix .test,$(OBJS))
	@echo "[*] static analysis"
	@luacheck --codes --formatter TAP . --exclude-files *.test.lua config.lua warp/vendor warp/config.lua
	@echo "[*] unit tests"
	@busted --lua=$(LUA) -o TAP
clean:
	$(RM) $(CLIB)
$(CLIB): src/utils.c src/murmurhash3.c
	$(CC) $(CFLAGS) -shared $^ -o $(CLIB)
install:
	$(INSTALL) -d $(PREFIX_LMOD)/dns
	$(INSTALL) $(EXTRA) $(PREFIX_LMOD)/dns
	$(INSTALL) $(LIBS) $(CLIB) $(PREFIX_LMOD)/
uninstall:
	rm -f $(addprefix $(PREFIX_LMOD)/,$(EXTRA) $(LIBS)) $(CLIB)
	rmdir $(PREFIX_LMOD)/dns

%.test: %.test.lua $(CLIB)
	$(LUA) $<

.PHONY: all check install uninstall
