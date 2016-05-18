all: server.c
	gcc server.c -o server -lssl -lcrypto
clean:
	rm -f server
