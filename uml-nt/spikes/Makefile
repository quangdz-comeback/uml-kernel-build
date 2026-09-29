# uml-nt M0 spikes.
# In MSYS2 MINGW64 shell: `gcc` is the mingw-w64 gcc, `clang` is the
# mingw-w64 clang (used here ONLY as a Linux cross-compiler with lld).
MINGW_CC ?= gcc
CLANG    ?= clang
CFLAGS   ?= -O2 -Wall -Wextra

all: s1_veh.exe s2_xproc.exe s5_spawn.exe s3_launcher.exe payload.elf s6_scan.exe

s1_veh.exe s2_xproc.exe s5_spawn.exe s3_launcher.exe: spike_common.h
s1_veh.exe: s1_veh.c ; $(MINGW_CC) $(CFLAGS) $< -o $@
s2_xproc.exe: s2_xproc.c ; $(MINGW_CC) $(CFLAGS) $< -o $@
s5_spawn.exe: s5_spawn.c ; $(MINGW_CC) $(CFLAGS) $< -o $@
s3_launcher.exe: s3_launcher.c ; $(MINGW_CC) $(CFLAGS) $< -o $@
s6_scan.exe: s6_scan.c ; $(MINGW_CC) $(CFLAGS) $< -o $@

payload.elf: s4_payload.c
	$(CLANG) --target=x86_64-linux-gnu -ffreestanding -fno-stack-protector \
		-nostdlib -static -no-pie -O2 -fuse-ld=lld -Wl,-e,_start -Wl,--build-id=none -o $@ $<

clean:
	rm -f s1_veh.exe s2_xproc.exe s5_spawn.exe s3_launcher.exe s6_scan.exe payload.elf results/*.json
.PHONY: all clean
