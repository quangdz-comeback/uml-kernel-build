# Monolithic static vde_plug for UML VECTOR transport
# Replaces: vde_plug + libvdeplug.so + libvdeplug_slirp.so (+ all their deps)
# Single binary, zero runtime dependencies, ~2.0M stripped.
#
# Usage:
#   make                    — dynamic build (needs libvdeslirp-dev)
#   make static             — fully static build
#   make static-ci          — CI build with custom libvdeslirp path

CC      ?= gcc
CFLAGS  := -Wall -Wextra -O2
LDFLAGS :=

# For CI: set these to the libvdeslirp source/build dirs
VDESLIRP_SRC   ?=
VDESLIRP_BUILD ?=

ifneq ($(VDESLIRP_BUILD),)
  CFLAGS  += -I$(VDESLIRP_SRC) -I$(VDESLIRP_BUILD) -DSTATIC_BUILD
  LDFLAGS += -L$(VDESLIRP_BUILD)
endif

.PHONY: all static static-ci clean

all: vde_plug

vde_plug: vde_plug.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -lvdeslirp -lslirp \
		$$(pkg-config --cflags --libs glib-2.0) -lm

static: vde_plug.c
	$(CC) $(CFLAGS) -static -o vde_plug $< $(LDFLAGS) \
		-lvdeslirp -lslirp -lglib-2.0 -lpcre -lm -lpthread

clean:
	rm -f vde_plug
