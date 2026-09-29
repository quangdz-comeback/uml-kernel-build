# SPDX-License-Identifier: GPL-2.0
# os-Windows/skas Kbuild — mirror of os-Linux/skas module list (M1.3).
# ccflags không kế thừa từ make cấp trên → thêm -I tới include/ cha.
ccflags-y += -I$(src)/../include
ccflags-y += -Wno-missing-prototypes

obj-y := mem.o process.o
