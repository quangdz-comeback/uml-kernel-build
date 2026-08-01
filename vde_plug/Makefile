CC      ?= gcc
CFLAGS  := -Wall -Wextra -O2
LDFLAGS :=

# For CI: set these to the libvdeslirp source/build dirs
VDESLIRP_SRC   ?=
VDESLIRP_BUILD ?=

# Prefix of a locally built libslirp with an enlarged DHCP pool
# (NB_BOOTP_CLIENTS). Needed so a nested hypervisor guest can lease addresses
# to more than 16 containers. Empty = link the distro libslirp.
SLIRP_PREFIX   ?=

ifneq ($(VDESLIRP_BUILD),)
  CFLAGS  += -I$(VDESLIRP_SRC) -I$(VDESLIRP_BUILD) -DSTATIC_BUILD
  LDFLAGS += -L$(VDESLIRP_BUILD)
endif

ifneq ($(SLIRP_PREFIX),)
  CFLAGS   += -I$(SLIRP_PREFIX)/include
  SLIRP_LIB := $(firstword $(wildcard $(SLIRP_PREFIX)/lib/*/libslirp.a $(SLIRP_PREFIX)/lib/libslirp.a))
else
  SLIRP_LIB := -lslirp
endif

.PHONY: all static static-ci clean

all: vde_plug

vde_plug: vde_plug.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -lvdeslirp -lslirp \
		$$(pkg-config --cflags --libs glib-2.0) -lm

static: vde_plug.c
	$(CC) $(CFLAGS) -static -o vde_plug $< $(LDFLAGS) \
		-lvdeslirp $(SLIRP_LIB) -lglib-2.0 -lpcre -lm -lpthread

clean:
	rm -f vde_plug
