all:
	gcc main.c kernel.c -o run -lnet -lpcap -lpthread
