all: server.c transmit_server.c
	gcc -g server.c -o server -lssl -lcrypto -lev -pthread
	gcc -g transmit_server.c -o transmit_server -lssl -lcrypto -lpthread
clean:
	rm -f server transmit_server
