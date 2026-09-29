// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/file.c — file/fd abstraction for the NT backend.
 * Upstream: linux v6.18.37 arch/um/os-Linux/file.c
 *
 * M1.8: the physmem pseudo-fd (seek/read/write through the launcher's
 * shadow mapping of the guest-RAM section — the memfd analogue).
 *
 * M3.5: real host files for ubd backing images. fds are indices into a
 * small table of NtCreateFile handles; all I/O is synchronous
 * (FILE_SYNCHRONOUS_IO_NONALERT) with explicit offsets — no overlapped
 * I/O, no completion ports (that is the M4 optimization). Positional
 * I/O (os_pread_file/os_pwrite_file, what ubd's do_io uses) passes the
 * offset straight to NtReadFile/NtWriteFile; stream I/O keeps the
 * position in the table so os_seek_file stays a bookkeeping write.
 * Consequences, on purpose:
 *   - os_sync_file is a no-op (buffered cache; a machine crash may
 *     lose the tail of guest writes — acceptable for the POC),
 *   - os_lock_file is a no-op (single-instance; upstream's flock
 *     analogue lands with real multi-instance work),
 *   - os_falloc_punch/zeroes return -EOPNOTSUPP, which upstream ubd
 *     turns into BLK_STS_NOTSUPP and permanently disables
 *     discard/write-zeroes on the queue (graceful degradation through
 *     upstream's own path, no fork of the queue setup).
 */
#include <linux/errno.h>
#include <linux/stat.h> /* S_IFREG */
#include <os.h>
#include <stub-panic.h>
#include "internal.h"

/* fd offset state for the physmem pseudo-fd (upstream: the memfd's own
 * file position). */
static unsigned long long memfd_offset;

/* ---- host fd table (M3.5) --------------------------------------------- */
#define UML_NT_FD_MAX 16
static struct {
	HANDLE h;                 /* NtCreateFile handle; NULL = free */
	unsigned long long pos;   /* stream position for read/write */
} fds[UML_NT_FD_MAX];

static int fd_alloc(HANDLE h)
{
	int i;

	for (i = 1; i < UML_NT_FD_MAX; i++) {
		if (fds[i].h == NULL) {
			fds[i].h = h;
			fds[i].pos = 0;
			return i;
		}
	}
	return -EMFILE;
}

static HANDLE fd_handle(int fd)
{
	if (fd <= 0 || fd >= UML_NT_FD_MAX)
		return NULL;
	return fds[fd].h;
}

/* NTSTATUS -> -errno for the file paths (subset; ubd's open path
 * special-cases -ENOENT/-EROFS/-EACCES, so those must be exact). */
static int nt_err_to_errno(NTSTATUS s)
{
	switch (s) {
	case STATUS_OBJECT_NAME_NOT_FOUND:
		return -ENOENT;
	case STATUS_END_OF_FILE:
		return 0; /* read at/after EOF */
	case 0xC0000022: /* STATUS_ACCESS_DENIED */
		return -EACCES;
	case 0xC0000043: /* STATUS_SHARING_VIOLATION */
		return -EBUSY;
	case 0xC0000047: /* STATUS_DISK_FULL */
		return -ENOSPC;
	default:
		os_info("file.c: unmapped NTSTATUS 0x%08x\n", s);
		return -EIO;
	}
}

int os_stat_file(const char *file_name, struct uml_stat *buf)
{
	WCHAR wpath[512];
	UNICODE_STRING uni;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK iosb;
	LARGE_INTEGER size;
	NTSTATUS s;
	HANDLE h;
	long long len;

	__builtin_memset(buf, 0, sizeof(*buf));
	len = uml_nt_ntpath(file_name, wpath, 512);
	if (len < 0)
		return -ENOENT;

	uni.Length = (unsigned short)(len * 2);
	uni.MaximumLength = (unsigned short)(len * 2 + 2);
	uni.Buffer = wpath;
	oa.Length = sizeof(oa);
	oa.RootDirectory = NULL;
	oa.ObjectName = &uni;
	oa.Attributes = OBJ_CASE_INSENSITIVE;
	oa.SecurityDescriptor = NULL;
	oa.SecurityQualityOfService = NULL;

	s = nt->NtCreateFile(&h, FILE_GENERIC_READ, &oa, &iosb, NULL,
			     FILE_ATTRIBUTE_NORMAL,
			     FILE_SHARE_READ | FILE_SHARE_WRITE,
			     FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT,
			     NULL, 0);
	if (!NT_SUCCESS(s)) {
		os_info("stat_file: NtCreateFile(%s) failed %08x\n",
			file_name, s);
		return nt_err_to_errno(s);
	}

	/* NT data files are regular files; nobody in the ubd path needs
	 * richer mode bits (ust_dev/ust_ino fudges only feed the COW
	 * path, which we never take). */
	buf->ust_mode = S_IFREG | 0644;

	if (!nt->GetFileSizeEx(h, &size)) {
		os_info("stat_file: GetFileSizeEx(%s) failed\n", file_name);
		nt->NtClose(h);
		return -EIO;
	}
	buf->ust_size = (unsigned long long)size.QuadPart;
	nt->NtClose(h);
	return 0;
}

int os_stat_fd(const int fd, struct uml_stat *buf)
{
	stub_panic("file.c: os_stat_fd");
}

int os_access(const char *file, int mode)
{
	stub_panic("file.c: os_access");
}

int os_set_exec_close(int fd)
{
	stub_panic("file.c: os_set_exec_close");
}

int os_ioctl_generic(int fd, unsigned int cmd, unsigned long arg)
{
	stub_panic("file.c: os_ioctl_generic");
}

int os_get_ifname(int fd, char *namebuf)
{
	stub_panic("file.c: os_get_ifname");
}

int os_mode_fd(int fd, int mode)
{
	stub_panic("file.c: os_mode_fd");
}

int os_seek_file(int fd, unsigned long long offset)
{
	if (fd == UML_NT_MEMFD_PHYS) {
		memfd_offset = offset;
		return 0;
	}
	if (fd_handle(fd) == NULL)
		return -EBADF;
	fds[fd].pos = offset;
	return 0;
}

static int memfd_write(const void *buf, int count)
{
	char *dst = (char *)uml_boot.physmem_base + memfd_offset;

	if (memfd_offset + (unsigned long long)count >
	    uml_boot.physmem_size) {
		os_info("memfd write past end: off=%llu+%d\n",
			memfd_offset, count);
		return -1;
	}
	__builtin_memcpy(dst, buf, count);
	memfd_offset += count;
	return count;
}

static int memfd_read(void *buf, int count)
{
	char *src = (char *)uml_boot.physmem_base + memfd_offset;

	if (memfd_offset + (unsigned long long)count >
	    uml_boot.physmem_size) {
		os_info("memfd read past end: off=%llu+%d\n",
			memfd_offset, count);
		return -1;
	}
	__builtin_memcpy(buf, src, count);
	memfd_offset += count;
	return count;
}

/* Positional I/O against a host fd. len/count is an int by upstream
 * ABI; NtReadFile/NtWriteFile take ULONG. */
static int host_pread(int fd, void *buf, int len, unsigned long long offset)
{
	LARGE_INTEGER off;
	IO_STATUS_BLOCK iosb;
	NTSTATUS s;

	if (len <= 0)
		return 0;
	off.QuadPart = (long long)offset;
	s = nt->NtReadFile(fds[fd].h, NULL, NULL, NULL, &iosb, buf,
			   (ULONG)len, &off, NULL);
	if (!NT_SUCCESS(s))
		return nt_err_to_errno(s);
	return (int)iosb.Information;
}

static int host_pwrite(int fd, const void *buf, int count,
		       unsigned long long offset)
{
	LARGE_INTEGER off;
	IO_STATUS_BLOCK iosb;
	NTSTATUS s;

	if (count <= 0)
		return 0;
	off.QuadPart = (long long)offset;
	s = nt->NtWriteFile(fds[fd].h, NULL, NULL, NULL, &iosb, (PVOID)buf,
			    (ULONG)count, &off, NULL);
	if (!NT_SUCCESS(s))
		return nt_err_to_errno(s);
	return (int)iosb.Information;
}

int os_write_file(int fd, const void *buf, int count)
{
	if (fd == UML_NT_MEMFD_PHYS)
		return memfd_write(buf, count);
	if (fd_handle(fd) == NULL)
		return -EBADF;
	return host_pwrite(fd, buf, count, fds[fd].pos);
}

int os_read_file(int fd, void *buf, int count)
{
	int n;

	if (fd == UML_NT_MEMFD_PHYS)
		return memfd_read(buf, count);
	if (fd_handle(fd) == NULL)
		return -EBADF;
	n = host_pread(fd, buf, count, fds[fd].pos);
	if (n > 0)
		fds[fd].pos += (unsigned long long)n;
	return n;
}

int os_open_file(const char *file, struct openflags flags, int mode)
{
	WCHAR wpath[512];
	UNICODE_STRING uni;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK iosb;
	ACCESS_MASK desired;
	ULONG disposition;
	NTSTATUS s;
	HANDLE h;
	long long len;
	int fd;

	(void)mode; /* created images get default ACLs (POC) */

	len = uml_nt_ntpath(file, wpath, 512);
	if (len == -3 || len == -1)
		return -ENOENT;
	if (len < 0)
		return -ENAMETOOLONG;

	uni.Length = (unsigned short)(len * 2);
	uni.MaximumLength = (unsigned short)(len * 2 + 2);
	uni.Buffer = wpath;
	oa.Length = sizeof(oa);
	oa.RootDirectory = NULL;
	oa.ObjectName = &uni;
	oa.Attributes = OBJ_CASE_INSENSITIVE;
	oa.SecurityDescriptor = NULL;
	oa.SecurityQualityOfService = NULL;

	desired = 0;
	if (flags.r)
		desired |= FILE_GENERIC_READ;
	if (flags.w)
		desired |= FILE_GENERIC_WRITE;
	if (desired == 0)
		desired = FILE_GENERIC_READ;

	disposition = flags.c ? FILE_OPEN_IF : FILE_OPEN;

	s = nt->NtCreateFile(&h, desired, &oa, &iosb, NULL,
			     FILE_ATTRIBUTE_NORMAL,
			     FILE_SHARE_READ | FILE_SHARE_WRITE,
			     disposition, FILE_SYNCHRONOUS_IO_NONALERT,
			     NULL, 0);
	if (!NT_SUCCESS(s))
		return nt_err_to_errno(s);

	fd = fd_alloc(h);
	if (fd < 0) {
		nt->NtClose(h); /* table full — don't leak the handle */
		return fd;
	}
	return fd;
}

/* os_read_file/os_write_file: real for the physmem pseudo-fd (M1.8)
 * and for host files (M3.5). */

int os_sync_file(int fd)
{
	if (fd == UML_NT_MEMFD_PHYS)
		return 0;
	if (fd_handle(fd) == NULL)
		return -EBADF;
	/* POC: no NtFlushBuffersFile yet — see the header comment. */
	return 0;
}

int os_file_size(const char *file, unsigned long long *size_out)
{
	struct uml_stat buf;
	int err;

	err = os_stat_file(file, &buf);
	if (err < 0)
		return err;
	*size_out = buf.ust_size;
	return 0;
}

int os_pread_file(int fd, void *buf, int len, unsigned long long offset)
{
	if (fd == UML_NT_MEMFD_PHYS) {
		if (offset + (unsigned long long)len >
		    uml_boot.physmem_size)
			return 0; /* EOF, position untouched */
		__builtin_memcpy(buf,
				 (char *)uml_boot.physmem_base + offset,
				 len);
		return len;
	}
	if (fd_handle(fd) == NULL)
		return -EBADF;
	return host_pread(fd, buf, len, offset);
}

int os_pwrite_file(int fd, const void *buf, int count, unsigned long long offset)
{
	if (fd == UML_NT_MEMFD_PHYS) {
		if (offset + (unsigned long long)count >
		    uml_boot.physmem_size)
			return -1;
		__builtin_memcpy((char *)uml_boot.physmem_base + offset,
				 buf, count);
		return count;
	}
	if (fd_handle(fd) == NULL)
		return -EBADF;
	return host_pwrite(fd, buf, count, offset);
}

int os_file_modtime(const char *file, long long *modtime)
{
	stub_panic("file.c: os_file_modtime (COW-only upstream)");
}

int os_pipe(int *fd, int stream, int close_on_exec)
{
	stub_panic("file.c: os_pipe");
}

int os_set_fd_async(int fd)
{
	stub_panic("file.c: os_set_fd_async");
}

int os_clear_fd_async(int fd)
{
	stub_panic("file.c: os_clear_fd_async");
}

int os_set_fd_block(int fd, int blocking)
{
	stub_panic("file.c: os_set_fd_block");
}

int os_accept_connection(int fd)
{
	stub_panic("file.c: os_accept_connection");
}

int os_create_unix_socket(const char *file, int len, int close_on_exec)
{
	stub_panic("file.c: os_create_unix_socket — AF_UNIX is stream-only on NT; D8 routes via TCP/named pipe");
}

int os_shutdown_socket(int fd, int r, int w)
{
	stub_panic("file.c: os_shutdown_socket");
}

int os_dup_file(int fd)
{
	stub_panic("file.c: os_dup_file");
}

void os_close_file(int fd)
{
	HANDLE h;

	if (fd == UML_NT_MEMFD_PHYS)
		return; /* pseudo-fd: nothing to close */
	h = fd_handle(fd);
	if (h == NULL)
		return;
	fds[fd].h = NULL;
	nt->NtClose(h);
}

ssize_t os_rcv_fd_msg(int fd, int *fds, unsigned int n_fds,
		      void *data, size_t data_len)
{
	stub_panic("file.c: os_rcv_fd_msg — SCM_RIGHTS fd passing has no NT equivalent; redesign at M5");
}

int os_connect_socket(const char *name)
{
	stub_panic("file.c: os_connect_socket");
}

int os_file_type(char *file)
{
	stub_panic("file.c: os_file_type");
}

int os_file_mode(const char *file, struct openflags *mode_out)
{
	stub_panic("file.c: os_file_mode");
}

int os_lock_file(int fd, int excl)
{
	/* POC: no cross-instance locking (upstream flocks the image so
	 * two UMLs cannot share it). Single-instance boot only. */
	(void)fd;
	(void)excl;
	return 0;
}

/* os_flush_stdout moved to util.c (real, synchronous console) at M1.8. */

unsigned os_major(unsigned long long dev)
{
	stub_panic("file.c: os_major");
}

unsigned os_minor(unsigned long long dev)
{
	stub_panic("file.c: os_minor");
}

unsigned long long os_makedev(unsigned major, unsigned minor)
{
	stub_panic("file.c: os_makedev");
}

int os_falloc_punch(int fd, unsigned long long offset, int count)
{
	/* Report unsupported: upstream ubd maps this to
	 * BLK_STS_NOTSUPP and calls blk_queue_disable_discard, so the
	 * queue never tries discard again. FSCTL_ZERO_DATA is the M4
	 * real implementation. */
	(void)fd;
	(void)offset;
	(void)count;
	return -EOPNOTSUPP;
}

int os_falloc_zeroes(int fd, unsigned long long offset, int count)
{
	(void)fd;
	(void)offset;
	(void)count;
	return -EOPNOTSUPP;
}

int os_eventfd(unsigned int initval, int flags)
{
	stub_panic("file.c: os_eventfd — NT: event object behind the fd idiom");
}

int os_sendmsg_fds(int fd, const void *buf, unsigned int len,
		   const int *fds, unsigned int fds_num)
{
	stub_panic("file.c: os_sendmsg_fds — no NT equivalent; redesign at M5");
}

int os_poll(unsigned int n, const int *fds)
{
	stub_panic("file.c: os_poll — NT: IOCP/overlapped replaces poll (irq.c owns the loop)");
}

void *os_mmap_rw_shared(int fd, size_t size)
{
	stub_panic("file.c: os_mmap_rw_shared — NT: MapViewOfFile");
}

void *os_mremap_rw_shared(void *old_addr, size_t old_size, size_t new_size)
{
	stub_panic("file.c: os_mremap_rw_shared");
}
