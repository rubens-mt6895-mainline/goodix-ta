# Build the trustlet host for the Goodix gf_spi sensor (Redmi K50 / rubens).
#
# The TA maps itself at 0x400000 with MAP_FIXED, so the host has to be linked
# somewhere else: -Ttext-segment=0x10000000.  Do not drop that flag.

CROSS   ?= aarch64-linux-gnu-
CC      := $(CROSS)gcc
CFLAGS  := -O2 -static -Wall -Wno-unused-parameter
LDFLAGS := -Wl,-Ttext-segment=0x10000000
LDLIBS  := -lm

DESTDIR ?=
PREFIX  ?= /opt/goodixta

all: bin/ta_host

bin/ta_host: src/ta_host.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

install: bin/ta_host
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/ta
	install -m755 bin/ta_host $(DESTDIR)$(PREFIX)/bin/ta_host
	install -m644 bin/goodixfp.ta $(DESTDIR)$(PREFIX)/ta/goodixfp.ta

clean:
	rm -f bin/ta_host

.PHONY: all install clean
