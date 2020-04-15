all:ClientSSL.c ServerSSL.c
	gcc -o client ClientSSL.c -L/usr/lib -lssl -lcrypto -lpthread
	gcc -o server ServerSSL.c -L/usr/lib -lssl -lcrypto -lpthread
clean:
	rm -f server
	rm -f client
