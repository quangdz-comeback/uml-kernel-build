# SPDX-License-Identifier: GPL-2.0
# os-Windows/skas Kbuild — mirror of os-Linux/skas module list (M1.3).
# ccflags không kế thừa từ make cấp trên → thêm -I tới include/ cha
# (stub-impl.h) và tới os-Windows/ (internal.h — M1.8 process.c dùng).
ccflags-y += -I$(src)/../include
ccflags-y += -I$(src)/..
ccflags-y += -Wno-missing-prototypes

obj-y := mem.o process.o fault.o vma.o physalloc.o physbackend.o \
	 elf.o scan_patch.o stub_ctl.o init_blob.o
