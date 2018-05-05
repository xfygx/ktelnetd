ifneq ($(KERNELRELEASE),)
    obj-m	:= ftp.o

else
    KDIR	:= /lib/modules/2.6.9/build
    PWD		:= $(shell pwd)

    default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
endif

clean:
	rm -f *.o *.ko *.mod.c
