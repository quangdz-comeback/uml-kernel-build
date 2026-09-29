// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/ubd_user.c — user side of the ubd driver.
 * Upstream: linux v6.18.37 arch/um/drivers/ubd_user.c
 *
 * Upstream runs every I/O request on a helper thread fed by a pipe
 * (os_pipe + poll in ubd_read_poll/ubd_write_poll). This port has no
 * poll-able pipe (os_pipe PANICs) and the overlapped-NT-IO redesign is
 * M4 — so start_io_thread reports -ENOSYS, which upstream's
 * ubd_driver_init treats as "falling back to synchronous I/O", and the
 * drivers/Makefile patch makes ubd_kern.c's submit path honor that:
 * with thread_fd < 0, queue_rq runs do_io() inline and completes the
 * request immediately (blocking NtReadFile/NtWriteFile are fine there —
 * the alarm timer is a separate NT thread and keeps the guest's time
 * ticking during the wait).
 *
 * ubd_read_poll/ubd_write_poll exist only so upstream's io_thread()
 * body (linked from ubd_kern.c, never spawned here) keeps linking.
 */
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h> /* printk, KERN_INFO */
#include <os.h>
#include <stub-panic.h>

/* Declared in arch/um/drivers/ubd.h — a sibling directory, not on our
 * include path; the ABI is (int) -> int, so redeclare locally. */
int ubd_read_poll(int timeout);
int ubd_write_poll(int timeout);

int start_io_thread(struct os_helper_thread **td_out, int *fd_out)
{
	(void)td_out;
	*fd_out = -1;
	printk(KERN_INFO "ubd: no io thread on os-Windows "
	       "(M4: overlapped NT I/O) — requests run synchronously\n");
	return -ENOSYS;
}

int ubd_read_poll(int timeout)
{
	(void)timeout;
	return 0;
}

int ubd_write_poll(int timeout)
{
	(void)timeout;
	return 0;
}

/* ---- COW helpers (upstream: drivers/cow_user.c, libc-host code) -------
 *
 * CONFIG_BLK_DEV_COW_COMMON defaults to y with UBD, and ubd_kern.c
 * links these unconditionally — but upstream's cow_user.c is pure
 * libc-host code (unistd.h, arpa/inet.h), so it can never build under
 * D1. The stubs keep the link intact and declare COW unsupported:
 * read_cow_header returning -EINVAL is exactly how upstream marks a
 * plain (non-COW) backing file, which is all this backend accepts.
 * file_reader stays real: pread passthrough, arg = fd.
 */
int file_reader(__u64 offset, char *buf, int len, void *arg)
{
	return os_pread_file((int)(long)arg, buf, len, offset);
}

int read_cow_header(int (*reader)(__u64, char *, int, void *),
		    void *arg, __u32 *version_out,
		    char **backing_file_out, long long *mtime_out,
		    unsigned long long *size_out, int *sectorsize_out,
		    __u32 *align_out, int *bitmap_offset_out)
{
	(void)reader;
	(void)arg;
	(void)version_out;
	(void)backing_file_out;
	(void)mtime_out;
	(void)size_out;
	(void)sectorsize_out;
	(void)align_out;
	(void)bitmap_offset_out;
	return -EINVAL;
}

int init_cow_file(int fd, char *cow_file, char *backing_file,
		  int sectorsize, int alignment, int *bitmap_offset_out,
		  unsigned long *bitmap_len_out, int *data_offset_out)
{
	stub_panic("ubd: COW files unsupported on os-Windows");
}

int write_cow_header(char *cow_file, int fd, char *backing_file,
		     int sectorsize, int alignment,
		     unsigned long long *size)
{
	stub_panic("ubd: COW files unsupported on os-Windows");
}

void cow_sizes(int version, __u64 size, int sectorsize, int align,
	       int bitmap_offset, unsigned long *bitmap_len_out,
	       int *data_offset_out)
{
	stub_panic("ubd: COW files unsupported on os-Windows");
}
