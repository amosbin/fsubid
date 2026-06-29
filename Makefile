CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -D_GNU_SOURCE -O2
TARGET  = fsubid
SRC     = fsubid.c
OUTDIR  = bin
BUILD_TARGET = $(OUTDIR)/$(TARGET)

PREFIX        ?= /usr/local
BINDIR        = $(PREFIX)/bin
ETCDIR        ?= /etc
CONF_SAMPLE   = fsubid.conf.sample

all: $(BUILD_TARGET)

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(BUILD_TARGET): $(SRC) | $(OUTDIR)
	$(CC) $(CFLAGS) -o $@ $<

install: $(BUILD_TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(BUILD_TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	install -d $(DESTDIR)$(ETCDIR)
	install -m 644 $(CONF_SAMPLE) $(DESTDIR)$(ETCDIR)/fsubid.conf.sample

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(ETCDIR)/fsubid.conf.sample

clean:
	rm -f $(BUILD_TARGET)
	rmdir $(OUTDIR) 2>/dev/null || true

.PHONY: all install uninstall clean
