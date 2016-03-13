PREFIX ?= /usr/local
LUA ?= luajit
ABIVER ?= 5.1
PREFIX_LMOD ?= $(PREFIX)/share/lua/$(ABIVER)
INSTALL ?= install
CFLAGS ?= -std=c99 -O2 -g -fPIC
LIBEXT := so

# Scripts and extras
OBJS := kdns
LIBS := $(addsuffix .lua,$(OBJS))
EXTRA := kdns/utils.lua kdns/io.lua kdns/rrparser.lua kdns/sift.lua
CLIB := kdns_clib.$(LIBEXT)

# Rules
all: check
check: $(addsuffix .test,$(OBJS))
clean:
	$(RM) $(CLIB)
$(CLIB): src/utils.c
	$(CC) $(CFLAGS) -shared $< -o $(CLIB)
install:
	$(INSTALL) -d $(PREFIX_LMOD)/kdns
	$(INSTALL) $(EXTRA) $(PREFIX_LMOD)/kdns
	$(INSTALL) $(LIBS) $(CLIB) $(PREFIX_LMOD)/
uninstall:
	rm -f $(addprefix $(PREFIX_LMOD)/,$(EXTRA) $(LIBS)) $(CLIB)
	rmdir $(PREFIX_LMOD)/kdns

%.test: %.test.lua $(CLIB)
	$(LUA) $<

.PHONY: all check install uninstall
