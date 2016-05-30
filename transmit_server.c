#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <pthread.h>
#include <unistd.h>

#define PORT_BEGIN 9000
#define THREAD_NUM 1
#define ENTRY_IP "140.123.103.190"
#define ENTRY_PORT 9000
#define MIDDLE_IP "140.123.103.191"
#define MIDDLE_PORT 9000
#define EXIT_IP "140.123.103.192"
#define EXIT_PORT 9000
#define MAXBUFF 2048
#define MY_NODE "middle"

typedef struct{
	int fd;
	int port;
}CONNECTION_INFO;

int server_init(int port);
void thread_func(void*data);

int main()
{
	int server_fd[THREAD_NUM];
	int i;
	pthread_t thread[THREAD_NUM];
	CONNECTION_INFO conn_info[THREAD_NUM];

	for (i=0;i<THREAD_NUM;i++){
		conn_info[i].fd=server_init(i);
		conn_info[i].port=PORT_BEGIN+i;
		pthread_create(&thread[i],NULL,(void*)thread_func,(void*)&conn_info[i]);
	}
	for (i=0;i<THREAD_NUM;i++)
		pthread_join(thread[i],NULL);

	return 0;
}


int server_init(int port)
{
	int fd;
	struct sockaddr_in addr;
	if ( (fd=socket(AF_INET,SOCK_STREAM,0)) <0 ){
		perror("socket open error at server_init\n");
		exit(1);
	}

	bzero((char*)&addr,sizeof(addr));
	addr.sin_family=AF_INET;
	addr.sin_port=PORT_BEGIN+port;
	addr.sin_addr.s_addr=INADDR_ANY;
	
	if ( bind(fd,(struct sockaddr*)&addr,sizeof(addr)) <0  ){
		perror("bind error at server_init\n");
		exit(1);
	}

	listen(fd,10);
	return fd;
}

void thread_func(void*data)
{
	CONNECTION_INFO*conn_info=(CONNECTION_INFO*)data;
	int prev_fd,prev_len;
	struct sockaddr_in prev_addr;
	char buff[MAXBUFF];
	bzero((char*)&prev_addr,sizeof(prev_addr));
	prev_len=sizeof(prev_addr);
	if( (prev_fd=accept(conn_info->fd,(struct sockaddr*)&prev_addr,&prev_len)) <0  ){
		printf("pthread accept connection error at port %d\n",conn_info->port);
		return;
	}

	recv(prev_fd,buff,MAXBUFF,0);
	printf("%s\n",buff);


}