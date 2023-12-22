obj-m += kfetch_mod_109550100.o

PWD := $(CURDIR) 

all: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

clean: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

load:
	sudo insmod kfetch_mod_109550100.ko

unload:
	sudo rmmod kfetch_mod_109550100.ko

test:
	gcc -o kfetch kfetch.c
	sudo ./kfetch -a

print:
	sudo dmesg | tail -n 10
