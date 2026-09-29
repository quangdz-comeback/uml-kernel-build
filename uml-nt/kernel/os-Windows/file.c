// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/file.c — file/fd abstraction for the NT backend.
 * Upstream: linux v6.18.37 arch/um/os-Linux/file.c
 *
 * Why a mirror of the os.h surface: the rest of the 6.18.37 kernel calls
 * only these names; the NT implementation (handles, overlapped IO,
 * named pipes) lands behind the same names in M1.7+.
 * Status: M1.3 skeleton — every entry point PANICs.
 */
#include <stub-impl.h>

int os_stat_file(const char *file_name, struct uml_stat *buf)
{
	stub_panic("file.c: os_stat_file");
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
	stub_panic("file.c: os_seek_file");
}

int os_open_file(const char *file, struct openflags flags, int mode)
{
	stub_panic("file.c: os_open_file");
}

int os_read_file(int fd, void *buf, int len)
{
	stub_panic("file.c: os_read_file");
}

int os_write_file(int fd, const void *buf, int count)
{
	stub_panic("file.c: os_write_file");
}

int os_sync_file(int fd)
{
	stub_panic("file.c: os_sync_file");
}

int os_file_size(const char *file, unsigned long long *size_out)
{
	stub_panic("file.c: os_file_size");
}

int os_pread_file(int fd, void *buf, int len, unsigned long long offset)
{
	stub_panic("file.c: os_pread_file");
}

int os_pwrite_file(int fd, const void *buf, int count, unsigned long long offset)
{
	stub_panic("file.c: os_pwrite_file");
}

int os_file_modtime(const char *file, long long *modtime)
{
	stub_panic("file.c: os_file_modtime");
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
	stub_panic("file.c: os_close_file");
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
	stub_panic("file.c: os_lock_file");
}

void os_flush_stdout(void)
{
	stub_panic("file.c: os_flush_stdout");
}

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
	stub_panic("file.c: os_falloc_punch — NT: DiscardVirtualMemory / FSCTL_ZERO_DATA");
}

int os_falloc_zeroes(int fd, unsigned long long offset, int count)
{
	stub_panic("file.c: os_falloc_zeroes");
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
