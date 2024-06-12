all:
	gcc methods.c kernel.c -o run -lnet -lpcap -lpthread
