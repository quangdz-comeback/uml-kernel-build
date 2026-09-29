# SPDX-License-Identifier: GPL-2.0
# os-Windows Kbuild — mirror of os-Linux module list.
# M1.3: every object PANICs; wiring into the Kbuild flow + ccflags
# (-Iinclude, noreland flags) lands with M1.4/M1.6.
# elf_aux.o intentionally absent: no host auxv on NT (D1).
# $(src) is absolute in kbuild 6.x (srcroot-based) — see Makefile.build.
ccflags-y += -I$(src)/include
# Skeleton-only: -Wmissing-prototypes fires because modules do not include
# <os.h> yet; prototypes arrive with the real implementation (M1.7+).
ccflags-y += -Wno-missing-prototypes

obj-y := file.o start_up.o mem.o process.o execvp.o helper.o umid.o \
	signal.o util.o time.o irq.o sigio.o tty.o registers.o main.o \
	user_syms.o stub-impl.o

# M3.5: ubd's user side — no io thread on NT (pipes/poll are the M4
# overlapped-IO redesign); start_io_thread reports -ENOSYS so the
# driver falls back to synchronous request execution (drivers patch).
obj-y += ubd_user.o

obj-y += skas/
