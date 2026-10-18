# KUtrace loadable module for NVIDIA Grace (arm64)
#   native build:  make
#   cross build:   make KDIR=/path/to/kernel/build ARCH=arm64 LLVM=1

KDIR ?= /lib/modules/$(shell uname -r)/build

obj-m += kutrace_mod.o

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
