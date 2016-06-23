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
#include "hidden_info.h"
#include "aes.h"

#define IS_ENTRY 1

#if IS_ENTRY == 1
    #define NEXT_IP MIDDLE_IP
    #define NEXT_PORT MIDDLE_PORT
    #define MY_PORT ENTRY_PORT
#else
    #define NEXT_IP EXIT_IP
    #define NEXT_PORT EXIT_PORT
    #define MY_PORT MIDDLE_PORT
#endif

typedef struct cell_direction{
    struct cell_direction*next;
    uint32_t streamid;
    int next_fd,prev_fd;
}CELL_DIRECTION;

CELL_DIRECTION*cell_head;

int next_fd[THREAD_NUM];

struct ev_loop*my_loop=NULL;

static void init_from_prev(struct ev_loop*loop,struct ev_io*watcher,int revents);
static void handle_from_both(struct ev_loop*loop,struct ev_io*watcher,int revents);


int server_init(int port);
int connect_init(int port);


CELL_DIRECTION*init_cell(uint32_t streamid,int prev_fd,int next_fd);
void insert_cell(CELL_DIRECTION*ptr);
CELL_DIRECTION*search_cell(uint32_t streamid);
void total_recv(int fd,char*buff,uint32_t size,char func_name[]);
void total_send(int fd,char*buff,uint32_t size,char func_name[]);


int main()
{
    signal(SIGPIPE,SIG_IGN);
    int server_fd[THREAD_NUM];
    int i;
    struct ev_io*server_watcher,*next_watcher;

    my_loop=ev_default_loop(0);

    for (i=0;i<THREAD_NUM;i++){
	next_fd[i]=connect_init(NEXT_PORT+i);
	server_fd[i]=server_init(MY_PORT+i);
	if (next_fd[i]==-1)
	    exit(1);


	next_watcher=(struct ev_io*)malloc(sizeof(struct ev_io));
	next_watcher->data=NULL;

	ev_io_init(next_watcher,handle_from_both,next_fd[i],EV_READ);
	ev_io_start(my_loop,next_watcher);

	server_watcher=(struct ev_io*)malloc(sizeof(struct ev_io));
	server_watcher->data=(void*)&next_fd[i];

	ev_io_init(server_watcher,init_from_prev,server_fd[i],EV_READ);
	ev_io_start(my_loop,server_watcher);

    }

    ev_loop(my_loop,0);

    return 0;
}


int server_init(int port)
{
    int server_fd , option ,flag;
    struct sockaddr_in server_addr;
    if ( (server_fd=socket(AF_INET,SOCK_STREAM,0)) <0 ){
	perror("socket open error at server_init\n");
	exit(1);
    }

    bzero((char*)&server_addr,sizeof(server_addr));
    server_addr.sin_family=AF_INET;
    server_addr.sin_port=ENTRY_PORT+port;
    server_addr.sin_addr.s_addr=INADDR_ANY;

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



    if ( bind(server_fd,(struct sockaddr*)&server_addr,sizeof(server_addr)) <0  ){
	perror("bind error at server_init\n");
	exit(1);
    }

    listen(server_fd,5000);
    return server_fd;
}
int connect_init(int port)
{
    int tag_fd;
    struct sockaddr_in tag_addr;
    struct timeval time_opt={0};
    char buff[MAXBUFF];
    int option=1;
    uint32_t payload_len,result,temp;

    bzero((char*)&tag_addr,sizeof(tag_addr));

    tag_addr.sin_family=AF_INET;
    tag_addr.sin_port= htons(port);
    inet_aton(NEXT_IP,&tag_addr.sin_addr);

    //printf("connect to %s:%d\n",inet_ntoa(tag_addr.sin_addr),ntohs(tag_addr.sin_port));

    if ( (tag_fd=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP))  <0   ){  
	printf("client socket initial error\n");
	exit(1);
    }   

    time_opt.tv_sec=2;
    time_opt.tv_usec=0;
    if (  setsockopt(tag_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&time_opt, sizeof(time_opt)) ==-1 
	    ||  setsockopt(tag_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&time_opt, sizeof(time_opt)) ==-1 ) { 
	printf("setsocket error at client init\n");
	return -1; 
    }   

#ifdef SO_NOSIGPIPE             
    setsockopt(tag_fd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    if ( setsockopt(tag_fd, SOL_SOCKET, SO_REUSEADDR, (uint *)&option, sizeof(option)) ==-1  ) { 
	printf("setsocket error at client init\n");
	return -1; 
    }   



    if ( connect(tag_fd,(struct sockaddr*)&tag_addr,sizeof(tag_addr)) <0  ){  
	printf("connect error at client_init , %s\n",strerror(errno));
	return -1; 
    }   

    return tag_fd;

}

static void init_from_prev(struct ev_loop*loop,struct ev_io*watcher,int revents)
{

    if (revents&EV_ERROR){
	printf("EV_ERROR at init_from_prev\n");
	return;
    }

    int prev_fd , prev_len;
    struct sockaddr_in prev_addr;
    prev_len=sizeof(prev_addr);

    if ( (prev_fd=accept(watcher->fd,(struct sockaddr*)&prev_addr,&prev_len)) <0   ){
	printf("accept error at init_from_prev\n");
	return;
    }

    struct ev_io*prev_watcher=(struct ev_io*)malloc(sizeof(struct ev_io));
    prev_watcher->data=watcher->data;

    ev_io_init(prev_watcher,handle_from_both,prev_fd,EV_READ);
    ev_io_start(my_loop,prev_watcher);
}
static void handle_from_both(struct ev_loop*loop,struct ev_io*watcher,int revents)
{   
    if (revents&EV_ERROR){
	printf("EV_ERROR at init_from_prev\n");
	return;
    }
    
    char buff[MAXBUFF];
    uint32_t streamid,len;
    CELL_DIRECTION*ptr;
    int side_judge;

    if (watcher->data==NULL) //-----handle from next-----
	side_judge=1;
    else		     //-----handle from prev-----
	side_judge=0;


    total_recv(watcher->fd,buff,4,"handle_from_both");
    memcpy(&streamid,buff,4);
    total_recv(watcher->fd,buff+4,4,"handle_from_both");
    memcpy(&len,buff+4,4);

    ptr=search_cell(streamid);
    
    if (ptr==NULL && side_judge==0){
	int*next_fd=(int*)(watcher->data);
	ptr=init_cell(streamid,watcher->fd,*next_fd);
	insert_cell(ptr);
    }
    else if (ptr==NULL && side_judge==1){
	printf("error at handle_from_both and it is from next , can not find the streamid\n");
	exit(1);
    }

    total_recv(watcher->fd,buff+8,len,"handle_from_both");

    total_send(ptr->next_fd,buff,len+8,"handle_from_both");
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
