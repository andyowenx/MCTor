all: OP_server.c transmit_server.c exit_server.c
	gcc -g OP_server.c -o OP_server -lssl -lcrypto -lev -pthread
	gcc -g transmit_server.c -o transmit_server -lssl -lcrypto -lpthread
	gcc -g exit_server.c -o exit_server -lssl -lcrypto -lev -pthread
clean:
	rm -f OP_server transmit_server  exit_server
