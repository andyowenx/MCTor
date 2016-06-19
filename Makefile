all: OP_server.c transmit_server.c exit_server.c STor_OP.c aes.c
	gcc -c OP_server.c aes.c
	gcc -g aes.o OP_server.o -o OP_server -lssl -lcrypto -lev -pthread
	gcc -g transmit_server.c -o transmit_server -lssl -lcrypto -lpthread
	gcc -g exit_server.c -o exit_server -lssl -lcrypto -lev -pthread
	gcc -g STor_OP.c -o STor_OP -lssl -lcrypto -lev
clean:
	rm -f OP_server transmit_server  exit_server  STor_OP
