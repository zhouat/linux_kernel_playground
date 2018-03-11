obj-m += drv.o

CC=gcc
ccflags-y += "-g"
ccflags-y += "-O0"

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	sudo rmmod drv
	sudo insmod ./drv.ko
	sudo chmod 666 /dev/vulndrv
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -fr ./trigger
