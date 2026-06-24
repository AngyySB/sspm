BINARY := sspm
PREFIX ?= $(HOME)/.local
BINDIR := $(PREFIX)/bin

.PHONY: all build install uninstall clean

all: build

build:
	cargo build --release

install: build
	install -Dm755 target/release/$(BINARY) $(BINDIR)/$(BINARY)

uninstall:
	rm -f $(BINDIR)/$(BINARY)

clean:
	cargo clean
