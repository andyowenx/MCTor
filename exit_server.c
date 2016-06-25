#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <unistd.h>
#include <ev.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include "hidden_info.h"
#include "aes.h"


typedef struct cell_direction{
    struct cell_direction*next;
    uint32_t streamid;
    int next_fd,prev_fd;
}CELL_DIRECTION;

CELL_DIRECTION*cell_head;


struct ev_loop*my_loop=NULL;

static void init_from_middle(struct ev_loop*loop,struct ev_io*watcher,int revents);
static void handle_from_middle(struct ev_loop*loop,struct ev_io*watcher,int revents);
static void handle_from_outside(struct ev_loop*loop,struct ev_io*watcher,int revents);

int server_init(int port);
int connect_init(char*outside, int middle_fd,uint32_t streamid);


CELL_DIRECTION*init_cell(uint32_t streamid,int prev_fd,int next_fd);
void insert_cell(CELL_DIRECTION*ptr);
CELL_DIRECTION*search_cell(uint32_t streamid);
void total_recv(int fd,char*buff,uint32_t size,char func_name[]);
void total_send(int fd,char*buff,uint32_t size,char func_name[]);
void total_encrypt(char*inbuff,char*outbuff,uint32_t len);


int main()
{
    signal(SIGPIPE,SIG_IGN);
    int server_fd[THREAD_NUM];
    int i;
    struct ev_io*server_watcher,*next_watcher;

    my_loop=ev_default_loop(0);

    for (i=0;i<THREAD_NUM;i++){
	server_fd[i]=server_init(EXIT_PORT+i);


	server_watcher=(struct ev_io*)malloc(sizeof(struct ev_io));

	ev_io_init(server_watcher,init_from_middle,server_fd[i],EV_READ);
	ev_io_start(my_loop,server_watcher);

    }

    ev_loop(my_loop,0);

    return 0;
}


int server_init(int port)
{
    int server_fd;
    int flag,option;
    struct sockaddr_in server_addr;
    if ( (server_fd=socket(AF_INET,SOCK_STREAM,0)) <0){
	perror("socket open error\n");
	exit(1);
    }   

    bzero((char*)&server_addr,sizeof(server_addr));
    server_addr.sin_family=AF_INET;
    server_addr.sin_addr.s_addr=INADDR_ANY;
    server_addr.sin_port=htons(port);


    if ( (flag=fcntl(server_fd,F_GETFL,0))==-1  ){  
	perror("fcntl error in F_GETFL\n");
	exit(1);
    }   
    if (fcntl(server_fd,F_SETFL,flag|O_NONBLOCK)==-1  ){  
	perror("fcntl error in F_SETFL\n");
	exit(1);
    }   

    option=1;
    if (  setsockopt(server_fd,SOL_SOCKET,SO_REUSEADDR,(uint*)&option , sizeof(option)) ==-1    ){  
	perror("setsockopt error\n");
	exit(1);
    }   


    if  ( bind(server_fd,(struct sockaddr*)&server_addr,sizeof(server_addr)) <0  ){  
	perror("bind error\n");
	exit(1);
    }   
    listen(server_fd,5000);
    return server_fd;

}
int connect_init(char*outside, int middle_fd,uint32_t streamid)
{
    int client_fd,client_len;
    struct sockaddr_in client_addr;
    struct timeval time_opt={0};
    char buff[MAXBUFF];
    int option=1;
    uint16_t port;
    uint32_t payload_len,result,temp;

    bzero((char*)&client_addr,sizeof(client_addr));
    memcpy(&port,outside+4,2);

    client_addr.sin_family=AF_INET;
    client_addr.sin_port= port;
    memcpy(&client_addr.sin_addr.s_addr,outside,4);

    printf("connect to %s:%d\n",inet_ntoa(client_addr.sin_addr),ntohs(client_addr.sin_port));

    if ( (client_fd=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP))  <0   ){  
	printf("client socket initial error\n");
	return -1; 
    }   

    time_opt.tv_sec=2;
    time_opt.tv_usec=0;
    if (  setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&time_opt, sizeof(time_opt)) ==-1 
	    ||  setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&time_opt, sizeof(time_opt)) ==-1 ) { 
	printf("setsocket error at client init\n");
	return -1; 
    }   

#ifdef SO_NOSIGPIPE             
    setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    if ( setsockopt(client_fd, SOL_SOCKET, SO_REUSEADDR, (uint *)&option, sizeof(option)) ==-1  ) { 
	printf("setsocket error at client init\n");
	return -1; 
    }   



    if ( connect(client_fd,(struct sockaddr*)&client_addr,sizeof(client_addr)) <0  ){  
	printf("connect error at client_init , %s\n",strerror(errno));
	return -1; 
    }   
    //-----reply outside addr info to browser-----
    payload_len=10;

    memcpy(buff,&streamid,4);
    memcpy(buff+4,&payload_len,4);

    memcpy(buff+8, "\x05\x00\x00\x01", 4);                                  
    memcpy(buff + 12, &(client_addr.sin_addr.s_addr), 4);
    memcpy(buff + 16, &(client_addr.sin_port), 2);

    //-----encrypt-----
    total_encrypt(buff+8,buff+8,payload_len);

    total_send(middle_fd,buff,payload_len+8,"connect_init");
    //printf("send to middle ok , len=%d at connect init\n",payload_len+8);

    return client_fd;

}

static void init_from_middle(struct ev_loop*loop,struct ev_io*watcher,int revents)
{

    if (revents&EV_ERROR){
	printf("EV_ERROR at init_from_middle\n");
	return;
    }   

    int prev_fd , prev_len;
    struct sockaddr_in prev_addr;
    prev_len=sizeof(prev_addr);

    if ( (prev_fd=accept(watcher->fd,(struct sockaddr*)&prev_addr,&prev_len)) <0   ){  
	printf("accept error at init_from_middle\n");
	return;
    }   

    struct ev_io*prev_watcher=(struct ev_io*)malloc(sizeof(struct ev_io));

    ev_io_init(prev_watcher,handle_from_middle,prev_fd,EV_READ);
    ev_io_start(my_loop,prev_watcher);
}


static void handle_from_middle(struct ev_loop*loop,struct ev_io*watcher,int revents)
{   
    if (revents&EV_ERROR){
	printf("EV_ERROR at handle_from_middle\n");
	return;
    }

    char buff[MAXBUFF];
    uint32_t streamid,len;
    CELL_DIRECTION*ptr;

    total_recv(watcher->fd,buff,4,"handle_from_middle");
    memcpy(&streamid,buff,4);
    total_recv(watcher->fd,buff+4,4,"handle_from_middle");
    memcpy(&len,buff+4,4);

    ptr=search_cell(streamid);


    //printf("recv from middle , streamid=%d , len=%d\n",streamid,len);

    total_recv(watcher->fd,buff+8,len,"handle_from_both");

    //-----decrypt-----
    //if (len>0 && len <=4096)
    	aesctr_encrypt(buff+8,buff+8,len,EXIT_KEY);

    if (ptr==NULL){
	int outside_fd=connect_init(buff+8,watcher->fd,streamid);
	if (outside_fd==-1){
	    len=10;

	    memcpy(buff,&streamid,4);
	    memcpy(buff+4,&len,4);
	    memcpy(buff+8,"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00",10);

	    //-----encrypt-----
	    total_encrypt(buff+8,buff+8,10);

	    total_send(watcher->fd,buff,len+8,"handle_from_middle");
	    printf("connect error , send to middle len=%d to drop connection\n",len);

	    return;
	}

	ptr=init_cell(streamid,watcher->fd,outside_fd);
	insert_cell(ptr);

	struct ev_io*outside_watcher=(struct ev_io*)malloc(sizeof(struct ev_io));
	outside_watcher->data=(void*)ptr;

	ev_io_init(outside_watcher,handle_from_outside,outside_fd,EV_READ);
	ev_io_start(my_loop,outside_watcher);
    }
    else
	total_send(ptr->next_fd,buff+8,len,"handle_from_middle");
}

static void handle_from_outside(struct ev_loop*loop,struct ev_io*watcher,int revents)
{
    char buff[MAXBUFF];
    int result;
    uint32_t len;
    if (EV_ERROR & revents){
	printf("revents error at read browser\n");
	return;
    }

    CELL_DIRECTION*ptr=(CELL_DIRECTION*)watcher->data;

    //-----the first eight bytes are stream id and payload length
    result=recv(watcher->fd,buff+8,MAXRECV,0);

    if (result<=0){
	ev_io_stop(my_loop,watcher);
	free(watcher);
	return;
    }

    //-----encrypt payload-----
    total_encrypt(buff+8,buff+8,result);

    len=result;
    memcpy(buff,&(ptr->streamid),4);
    memcpy(buff+4,&len,4);

    total_send(ptr->prev_fd,buff,len+8,"handle_from_outside");
    printf("send to middle , streamid=%d , len=%d\n",ptr->streamid,len);

}

void total_send(int fd,char*buff,uint32_t len , char func_name[])
{
    uint32_t send_byte , temp , counter;
    for (send_byte=0 , temp=0 , counter=0  ;send_byte<len;      send_byte+=temp   ,counter++){
	temp=send(fd,buff+send_byte , len-send_byte,0);
	if (temp<0){
	    printf("send error at %s , %s\n",func_name,strerror(errno));
	    exit(1);
	}   
	if (counter>10){
	    printf("stay at send loop too long , fd=%d , len=%d  , func=%s\n",fd,len,func_name);
	    exit(1);
	}   
    }   
}
void total_recv(int fd,char*buff,uint32_t len , char func_name[])
{
    uint32_t recv_byte , temp ,counter;
    for (recv_byte=0, temp=0 , counter=0  ; recv_byte<len  ; recv_byte+=temp , counter++  ){  
	temp=recv(fd,buff+recv_byte, len-recv_byte , 0); 
	if (temp==0){
	    printf("recv EOF at %s\n",func_name);
	    return;
	}   
	else if (temp<0){
	    printf("recv error at %s , %s\n",func_name,strerror(errno));
	    exit(1);
	}   
	if (counter>10){
	    printf("stay at recv loop too long , fd=%d , len=%d\n , func=%s\n",fd,len,func_name);
	    exit(1);
	}   
    }   
}

void total_encrypt(char*inbuff,char*outbuff,uint32_t len)
{
    if (len<0 || len>4096)
	return;
    aesctr_encrypt(inbuff,outbuff,len,EXIT_KEY);
    aesctr_encrypt(inbuff,outbuff,len,ENTRY_KEY);
    aesctr_encrypt(inbuff,outbuff,len,MIDDLE_KEY);

}

CELL_DIRECTION*init_cell(uint32_t streamid,int prev_fd,int next_fd)
{
    CELL_DIRECTION*ptr=(CELL_DIRECTION*)malloc(sizeof(CELL_DIRECTION));
    ptr->next=NULL;
    ptr->streamid=streamid;
    ptr->prev_fd=prev_fd;
    ptr->next_fd=next_fd;
}

void insert_cell(CELL_DIRECTION*ptr)
{
    CELL_DIRECTION*walker;
    if (cell_head==NULL){
	cell_head=ptr;
	return;
    }

    for(walker=cell_head;walker->next!=NULL;walker=walker->next)
	;

    walker->next=ptr;
}

CELL_DIRECTION*search_cell(uint32_t streamid)
{
    CELL_DIRECTION*walker;
    for ( walker=cell_head;walker!=NULL;walker=walker->next  ){
	if (walker->streamid==streamid)
	    return walker;
    }

    return NULL;
}
