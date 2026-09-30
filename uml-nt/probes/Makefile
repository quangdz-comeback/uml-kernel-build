# SPDX-License-Identifier: GPL-2.0
# uml-nt probes — host-side evidence tools (native Windows CI).
#
#   make          → build every probe exe
#   make run-*    → run one locally (wine gives rough answers only;
#                   the CI native runner is the arbiter)
#
# probes are NOT gates: they print markers and exit 0 so the workflow
# log always carries the evidence for the design decision at hand.

MINGW_CC := x86_64-w64-mingw32-gcc
PROBES := fsgsbase xstate

all: $(PROBES:%=%.exe)

%.exe: %.c
	$(MINGW_CC) -O2 -Wall -Wextra -static -o $@ $<

run-%: %.exe
	./$*.exe

clean:
	rm -f $(PROBES:%=%.exe)

.PHONY: all clean run-%
