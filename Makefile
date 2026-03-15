CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -Wpedantic -O2 -g
LDFLAGS ?=

TARGET  := slirp
SRC     := slirp.c

# ── Static build paths (adjust if your libvdeslirp checkout is elsewhere) ──
VDESLIRP_SRC   ?= /tmp/libvdeslirp
VDESLIRP_BUILD ?= $(VDESLIRP_SRC)/build
SYSLIB         := /usr/lib/x86_64-linux-gnu

.PHONY: all static clean

# ── Default: dynamic link ──
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lvdeslirp -lyaml

# ── Static: fully portable binary ──
static: $(SRC) $(VDESLIRP_BUILD)/libvdeslirp.a
	$(CC) $(CFLAGS) -static -DSTATIC_BUILD \
		-I$(VDESLIRP_SRC) -I$(VDESLIRP_BUILD) -I/usr/include/slirp \
		-o $(TARGET) $< \
		$(VDESLIRP_BUILD)/libvdeslirp.a \
		$(SYSLIB)/libyaml.a \
		$(SYSLIB)/libslirp.a \
		$(SYSLIB)/libglib-2.0.a \
		$(SYSLIB)/libpcre.a \
		-pthread -lm
	@echo "=== Static build complete ==="
	@file $(TARGET)
	@ls -lh $(TARGET)

clean:
	rm -f $(TARGET)
