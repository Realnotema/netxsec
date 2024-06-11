all:
	gcc kernel.c -o run -lnet -lpcap -lpthread
