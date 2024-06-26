all:
	gcc methods.c kernel.c -o run -lnet -lpcap -lpthread
	
test:
	gcc -o tests/kernel_test tests/kernel_test.c kernel.c -I/opt/homebrew/opt/cunit/include -L/opt/homebrew/opt/cunit/lib -lcunit -ldl -lpcap -lnet
	gcc -o tests/methods_test tests/methods_test.c methods.c kernel.c -I/opt/homebrew/opt/cunit/include -L/opt/homebrew/opt/cunit/lib -lcunit -ldl -lpcap -lnet
	./tests/kernel_test
	sudo ./tests/methods_test