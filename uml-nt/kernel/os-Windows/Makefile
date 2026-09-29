# SPDX-License-Identifier: GPL-2.0
# os-Windows Kbuild — mirror of os-Linux module list.
# M1.3: every object PANICs; wiring into the Kbuild flow + ccflags
# (-Iinclude, noreland flags) lands with M1.4/M1.6.
# elf_aux.o intentionally absent: no host auxv on NT (D1).
obj-y := file.o start_up.o mem.o process.o execvp.o helper.o umid.o \
	signal.o util.o time.o irq.o sigio.o tty.o registers.o main.o \
	user_syms.o stub-impl.o

obj-y += skas/
