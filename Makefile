PREFIX ?= /usr/local
LUA ?= luajit
ABIVER ?= 5.1
PREFIX_LMOD ?= $(PREFIX)/share/lua/$(ABIVER)
INSTALL ?= install

# Scripts and extras
OBJS := kdns
LIBS := $(addsuffix .lua,$(OBJS))
EXTRA := kdns/utils.lua kdns/io.lua kdns/rrparser.lua

# Rules
all: check
check: $(addsuffix .test,$(OBJS))
install:
	$(INSTALL) -d $(PREFIX_LMOD)/kdns
	$(INSTALL) $(EXTRA) $(PREFIX_LMOD)/kdns
	$(INSTALL) $(LIBS) $(PREFIX_LMOD)/
uninstall:
	rm -f $(addprefix $(PREFIX_LMOD)/,$(EXTRA) $(LIBS))
	rmdir $(PREFIX_LMOD)/kdns

%.test: %.test.lua
	$(LUA) $<

.PHONY: all check install uninstall
