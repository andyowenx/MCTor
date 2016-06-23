all: OP_server.c transmit_server.c exit_server.c aes.c
	gcc -c -g OP_server.c aes.c exit_server.c transmit_server.c
	gcc aes.o OP_server.o -o OP_server -lssl -lcrypto -lev -pthread
	gcc transmit_server.o aes.o -o transmit_server -lssl -lcrypto  -lev
	gcc exit_server.o aes.o -o exit_server -lssl -lcrypto -lev -pthread
clean:
	rm -f OP_server transmit_server  exit_server
