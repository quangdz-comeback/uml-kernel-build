/* SPDX-License-Identifier: GPL-2.0 */
/*
 * physalloc.h — guest physical run allocator (M3.2), uml-nt.
 *
 * Upstream analogue: the host-memory allocators in arch/um/os-Linux
 * (host mmap hands out pages; UML's physmem is a temp file/memfd). On
 * NT the whole guest physmem is ONE pagefile-backed section; the stub
 * maps per-VMA VIEWS of it at guest VAs — and MapViewOfFile's offset
 * must be 64 KiB-aligned (system allocation granularity). The
 * allocator therefore hands out 64 KiB RUNS, not 4 KiB pages: a VMA's
 * backing always starts 64K-aligned so one MapViewOfFileEx covers it.
 *
 * COW (ARCHITECTURE §4): runs carry a refcount. A fork CLONE bumps
 * the refcount of every run its VMAs point at; the first write-fault
 * copies the dirtied 4 KiB page into a fresh run (the copy itself is
 * kernel-side memcpy through the kernel's own flat view — this module
 * only tracks who owns what) and splits the VMA there.
 *
 * Pure logic, no kernel includes: unit-tested standalone on Linux CI.
 */
#ifndef __UM_OS_WINDOWS_PHYSALLOC_H
#define __UM_OS_WINDOWS_PHYSALLOC_H

#define UML_NT_PHYS_RUN_SHIFT  16ull /* 64 KiB — MapViewOfFile offset granularity */
#define UML_NT_PHYS_RUN_SIZE   (1ull << UML_NT_PHYS_RUN_SHIFT)
#define UML_NT_PHYS_MAX_RUNS   4096  /* 4096 * 64K = 256 MiB POC ceiling */

struct uml_nt_phys {
	unsigned long long size;      /* section bytes (rounded to runs) */
	unsigned short refs[UML_NT_PHYS_MAX_RUNS]; /* 0 = free run */
};

/* Initialize over a section of `size` bytes. Returns 0, or -1 if size
 * exceeds UML_NT_PHYS_MAX_RUNS runs. */
int uml_nt_phys_init(struct uml_nt_phys *p, unsigned long long size);

/* Allocate one run: offset in bytes, or -1 when exhausted. */
long long uml_nt_phys_alloc(struct uml_nt_phys *p);

/* Claim a SPECIFIC free run (the kernel image occupies the section
 * head — the claimer burns [0, image_end) at init; VMAs then pin
 * their exact runs). Returns 0, -1 when the run is out of range or
 * already taken. */
int uml_nt_phys_alloc_at(struct uml_nt_phys *p, long long off);

/* refcount helpers. unref returns the refcount AFTER the drop (the
 * caller frees the content when it reaches 0 — pages read back zero
 * in a pagefile section, no scrubbing needed). -1 on bad offsets. */
int uml_nt_phys_ref(struct uml_nt_phys *p, long long off);
int uml_nt_phys_unref(struct uml_nt_phys *p, long long off);
int uml_nt_phys_refs(struct uml_nt_phys *p, long long off);

#endif /* __UM_OS_WINDOWS_PHYSALLOC_H */
