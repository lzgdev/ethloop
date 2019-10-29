ifneq ($(KERNELRELEASE),)
# kbuild part of makefile
#
# Makefile for the Intel(R) Gigabit Ethernet Linux Driver
#

obj-$(CONFIG_ETHLOOP) := ethloop.o

ethloop-y := elb_main.o

else    # ifneq($(KERNELRELEASE),)

DIR_BUILD=/lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(DIR_BUILD) M=$(PWD) CONFIG_ETHLOOP=m modules

clean:
	$(MAKE) -C $(DIR_BUILD) M=$(PWD) CONFIG_ETHLOOP=m clean

endif   # ifneq($(KERNELRELEASE),)

