# KUtrace loadable module
#   native build:  make
#   cross build:   make KDIR=/path/to/kernel/build ARCH=arm64 LLVM=1
#   Raspberry Pi4: make KUTRACE_TARGET=rpi4

KDIR ?= /lib/modules/$(shell uname -r)/build

# -march=native only makes sense for x86 (it selects AMD vs Intel code paths).
# On arm64 it would also break cross builds, and the kernel picks -march itself.
ifeq ($(SRCARCH),x86)
ccflags-y += -march=native
endif
ifeq ($(KUTRACE_TARGET),rpi4)
ccflags-y += -DKUTRACE_RPI4
endif

obj-m += kutrace_mod.o

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
