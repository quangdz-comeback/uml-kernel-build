// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/main.c — UML host-process entry.
 * Upstream: linux v6.18.37 arch/um/os-Linux/main.c
 *
 * Upstream main() runs as a normal host process with libc; here the
 * launcher.exe maps vmlinux.elf and jumps to the entry with a prepared
 * stack (S3/S5 pattern), so the C entry shape is decided in M1.7/M1.8.
 * The malloc __wrap_* interposers upstream are dead here: D1 forbids
 * host libc — the kernel heap becomes RtlAllocateHeap. Status: skeleton.
 */
#include <stub-impl.h>

int main(int argc, char **argv, char **envp)
{
	stub_panic("main.c: main — entry shape (cmdline via launcher stack) lands in M1.7/M1.8");
}
