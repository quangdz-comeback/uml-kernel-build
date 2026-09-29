// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/mem.c — per-mm syscall batching toward the stub.
 * Upstream: linux v6.18.37 arch/um/os-Linux/skas/mem.c
 *
 * Upstream flushes mmap/munmap batches into stub_data and pokes the
 * stub; the NT backend issues kernel-side VirtualAlloc/VirtualProtect
 * commands through the shared cmd-slot instead (S2 protocol, id
 * monotonic dedupe — pitfall 4.4). Status: M1.3 skeleton — PANICs.
 */
#include <stub-impl.h>

int syscall_stub_flush(struct mm_id *mm_idp)
{
	stub_panic("skas/mem.c: syscall_stub_flush");
}

struct stub_syscall *syscall_stub_alloc(struct mm_id *mm_idp)
{
	stub_panic("skas/mem.c: syscall_stub_alloc");
}

void syscall_stub_dump_error(struct mm_id *mm_idp)
{
	stub_panic("skas/mem.c: syscall_stub_dump_error");
}

int map(struct mm_id *mm_idp, unsigned long virt, unsigned long len,
	int prot, int phys_fd, unsigned long long offset)
{
	stub_panic("skas/mem.c: map — NT: VirtualAlloc in physmem section + cmd to stubs");
}

int unmap(struct mm_id *mm_idp, unsigned long addr, unsigned long len)
{
	stub_panic("skas/mem.c: unmap");
}
