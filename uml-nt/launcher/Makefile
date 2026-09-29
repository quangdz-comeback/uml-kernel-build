# uml-nt launcher.exe (M1.8) — mingw PE program.
# In MSYS2 MINGW64 shell, `gcc` is the mingw-w64 compiler.
MINGW_CC ?= gcc
CFLAGS   ?= -O2 -Wall -Wextra

# One header source for launcher and kernel: include straight from the
# kernel overlay (D9 — drift fails to compile, never at boot).
KINC = ../kernel/overlay/arch/um/include/shared

all: launcher.exe

launcher.exe: launcher.c $(KINC)/ntabi.h $(KINC)/boot-info.h
	$(MINGW_CC) $(CFLAGS) -I $(KINC) $< -o $@

clean:
	rm -f launcher.exe
.PHONY: all clean
