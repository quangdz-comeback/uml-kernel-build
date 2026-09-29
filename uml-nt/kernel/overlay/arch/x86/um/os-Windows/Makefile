#
# uml-nt: x86/um NT backend (mirror of os-Linux module list).
# tls.o kept unconditionally for link parity (PANICs if reached — D1).
# stub-panic.h lives with the um os-Windows scaffolding include dir.
ccflags-y += -I$(srctree)/arch/um/os-Windows/include
ccflags-y += -Wno-missing-prototypes
obj-y = registers.o mcontext.o tls.o stub-impl.o

include $(srctree)/arch/um/scripts/Makefile.rules
