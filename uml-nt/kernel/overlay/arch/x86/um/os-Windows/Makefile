#
# uml-nt: x86/um NT backend (mirror of os-Linux module list).
# tls.o kept unconditionally for link parity (PANICs if reached — D1).
# Skeleton-only: -Wmissing-prototypes until real headers land (M2).
ccflags-y += -Wno-missing-prototypes
obj-y = registers.o mcontext.o tls.o stub-impl.o

include $(srctree)/arch/um/scripts/Makefile.rules
