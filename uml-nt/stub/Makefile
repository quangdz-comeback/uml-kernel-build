# SPDX-License-Identifier: GPL-2.0
# stub.exe — uml-nt stub process (D3: PE mingw, static).
#
# Kernel-side consumers include stub_nt.h via the overlay path below —
# one header source for both sides (same rule as launcher ↔ ntabi.h).
MINGW_CC := x86_64-w64-mingw32-gcc
KERNELDIR := $(CURDIR)/../kernel/overlay/arch/um

CFLAGS  := -O2 -Wall -Wextra -static
CFLAGS  += -I$(KERNELDIR)/include/shared

stub.exe: stub.c $(KERNELDIR)/include/shared/stub_nt.h
	$(MINGW_CC) $(CFLAGS) -o $@ stub.c

clean:
	rm -f stub.exe

.PHONY: clean
