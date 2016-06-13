#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <ev.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "hidden_info.h"
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>

#define debug 1

typedef struct conn_info{
	struct conn_info*next;
	int browser_fd;
	uint32_t streamid;
	uint32_t thread_id;
	struct ev_io*watcher;
}CONN_INFO;



typedef struct {
	uint8_t ver;        
	uint8_t nmethods;
	uint8_t methods[0];
} socks5_method_req_t;

typedef struct {
	uint8_t ver;
	uint8_t method;
} socks5_method_res_t;

typedef struct {
	uint8_t ver;
	uint8_t cmd;
	uint8_t rsv;
	uint8_t addrtype;
} socks5_request_t;




struct ev_loop *my_loop=NULL;
CONN_INFO info_head[THREAD_NUM];
uint32_t streamid_master=0;
int entry_fd[THREAD_NUM];

int server_init(int port);
void error_report(int kind,int num,int browser_fd);
uint32_t get_streamid(void);
uint32_t connection_distribute(uint32_t streamid);
void my_send(int fd,char*buff,int size,char func_name[]);

static void init_from_browser(struct ev_loop*loop,struct ev_io*watcher,int revents);
static void handle_from_browser(struct ev_loop*loop,struct ev_io*watcher,int revents);
static void handle_from_entry(struct ev_loop*loop,struct ev_io*watcher,int revents);

CONN_INFO*info_init(int browser_fd,uint32_t streamid,uint32_t thread_id,struct ev_io*browser_watcher);
void info_insert(CONN_INFO*head,CONN_INFO*tag);
void info_delete(CONN_INFO*head,CONN_INFO*tag);
CONN_INFO*info_search(CONN_INFO*head,int streamid);


int main()
{
	signal(SIGPIPE,SIG_IGN);

	int server_fd;
	int i;
	struct ev_io browser_watcher,entry_watcher[THREAD_NUM];
	struct sockaddr_in entry_addr[i];

	server_fd=server_init(OP_PORT);

	my_loop=ev_default_loop(0);


	for (i=0;i<THREAD_NUM;i++){
		bzero((char*)&entry_addr[i],sizeof(entry_addr[i]));
		if ( (entry_fd[i]=socket(AF_INET,SOCK_STREAM,0)) <0  ){
			printf("entry socket open error\n");
			exit(1);
		}
		entry_addr[i].sin_family=AF_INET;
		entry_addr[i].sin_port=htons(ENTRY_PORT+i);
		inet_aton(ENTRY_IP,&(entry_addr[i].sin_addr));

		if ( connect(entry_fd[i],(struct sockaddr*)&entry_addr[i],sizeof(entry_addr[i])) <0 ){
			printf("connect to entry error\n");
			exit(1);
		}

		info_head[i].streamid=-1;
		info_head[i].thread_id=i;
		info_head[i].browser_fd=-1;
		info_head[i].next=NULL;
		info_head[i].watcher=NULL;
		
		entry_watcher->data=(void*)&info_head[i];

		ev_io_init(&entry_watcher[i],handle_from_entry,entry_fd[i],EV_READ);
		ev_io_start(my_loop,&entry_watcher[i]);
	}

	ev_io_init(&browser_watcher,init_from_browser,server_fd,EV_READ);
	ev_io_start(my_loop,&browser_watcher);

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


static void init_from_browser(struct ev_loop*loop,struct ev_io*watcher,int revents)
{

	if (revents&EV_ERROR){
		printf("revent error at init_from_browser\n");
		return;
	}

	int browser_fd ,browser_len;
	struct sockaddr_in browser_addr;
	browser_len=sizeof(browser_addr);

	if ( (browser_fd=accept(watcher->fd,(struct sockaddr*)&browser_addr,&browser_len)) <0 ){
		printf("accept browser connect fail\n");
		return;
	}

	//-----initial the proxy connection-----
	struct timeval time_opt={0};
	struct sockaddr_in outside_addr;
	int option=1 , hostname_len ,result,ret;
	char buff[MAXBUFF];
	time_opt.tv_sec=2;
	time_opt.tv_usec=0;

#ifdef SO_NOSIGPIPE                                                                                             
	setsockopt(browser_fd, SOL_SOCKET, SO_NOSIGPIPE, &option, sizeof(option));
#endif


	if ( (setsockopt(browser_fd,SOL_SOCKET,SO_RCVTIMEO,(char*)&time_opt,sizeof(time_opt))  == -1)
			|| (    setsockopt(browser_fd,SOL_SOCKET,SO_SNDTIMEO,(char*)&time_opt,sizeof(time_opt))  ==-1)  ){
		printf("setsockopt error at init_from_browser\n");
		return;
	}
	if ( setsockopt(browser_fd,SOL_SOCKET,SO_REUSEADDR,(uint*)&option,sizeof(option)) ==-1   ){
		printf("setsockopt reuse error at init_from_browser");
		return;
	}
	//-----proxy auth , step one-----
	if ( recv(browser_fd, buff, 2, 0)==-1){
		error_report(0,1,browser_fd);
		return;
	}
	if ( ((socks5_method_req_t *)buff)->ver  != 0x05 ){
		printf("This is not sock5 , disconnect\n");
		close(browser_fd);
		return;
	}
	ret = ((socks5_method_req_t *)buff)->nmethods;
	if ( recv(browser_fd, buff, ret, 0) ==-1){
		error_report(0,2,browser_fd);
		return;
	}

	// no auth
	memcpy(buff, "\x05\x00", 2);
	if (send(browser_fd, buff, 2, 0)==-1){
		error_report(1,3,browser_fd);
		return;
	}

	// REQUEST and REPLY
	if (recv(browser_fd, buff, 4, 0)==-1){
		error_report(0,4,browser_fd);
		return;
	}

	if ( ((socks5_request_t *)buff)->ver != 0x05
			||  ((socks5_request_t *)buff)->cmd !=0x01  ) {

		((socks5_request_t *)buff)->ver = 0x05;
		((socks5_request_t *)buff)->cmd = 0x07;
		((socks5_request_t *)buff)->rsv = 0;

		// cmd not supported
		send(browser_fd, buff, 4, 0);
		close(browser_fd);
		return;
	}

	if ( ((socks5_request_t *)buff)->addrtype ==0x01  ) {
		bzero((char *)&outside_addr, sizeof(outside_addr));
		outside_addr.sin_family = AF_INET;

		if ( recv(browser_fd, buff, 4, 0)==-1){
			error_report(0,5,browser_fd);
			return;
		}

		memcpy(&(outside_addr.sin_addr.s_addr), buff, 4);
		if ( recv(browser_fd, buff, 2, 0)==-1){
			error_report(0,6,browser_fd);
			return;
		}
		memcpy(&(outside_addr.sin_port), buff, 2);

		printf("type : IP, %s:%d\n", inet_ntoa(outside_addr.sin_addr), htons(outside_addr.sin_port));

	} else if ( ((socks5_request_t *)buff)->addrtype ==0x03) {
		struct hostent *hptr;

		bzero((char *)&outside_addr, sizeof(outside_addr));
		outside_addr.sin_family = AF_INET;

		if (recv(browser_fd, buff, 1, 0)==-1){
			error_report(0,7,browser_fd);
			return;
		}
		ret = buff[0];
		buff[ret] = 0;
		if (recv(browser_fd, buff, ret, 0)==-1){
			error_report(0,8,browser_fd);
			return;
		}
		//hptr = gethostbyname(buff);
		printf("type : domain [%s].\n", buff);

		if (NULL == hptr){
			printf("error at initial the proxy connection , hostent is NULL\n");
			close(browser_fd);
			return;
		}
		if (AF_INET != hptr->h_addrtype){
			printf("error at initial the proxy connection , it is not tcp\n");
			close(browser_fd);
			return;
		}
		if (NULL == *(hptr->h_addr_list)){
			printf("error at initial the proxy connection , h_add_list is NULL\n");
			close(browser_fd);
			return;
		}
		memcpy(&(outside_addr.sin_addr.s_addr), *(hptr->h_addr_list), 4);

		if (recv(browser_fd, buff, 2, 0)==-1){
			error_report(0,9,browser_fd);
			return;
		}
		memcpy(&(outside_addr.sin_port), buff, 2);
	} else {
		((socks5_request_t *)buff)->ver = 0x05;
		((socks5_request_t *)buff)->cmd = 0x08;
		((socks5_request_t *)buff)->rsv = 0;

		// cmd not supported
		send(browser_fd, buff, 4, 0);
		printf("error at initial the proxy connection , the connection command is not support\n");
		close(browser_fd);
		return;
	}

	//-----send the new address to entry server-----
	CONN_INFO*ptr=(CONN_INFO*)malloc(sizeof(CONN_INFO));
	struct ev_io*browser_watcher=(struct ev_io*)malloc(sizeof(struct ev_io));
	uint32_t streamid,thread_id,len=6;
	streamid=get_streamid();
	thread_id=connection_distribute(streamid);
	ptr=info_init(browser_fd,streamid,thread_id,browser_watcher);
	info_insert(&info_head[thread_id],ptr);
	
	browser_watcher->data=(void*)ptr;

	memcpy(buff,&streamid,4);
	memcpy(buff+4,&len,4);
	memcpy(buff+8,&(outside_addr.sin_addr.s_addr),4);
	memcpy(buff+12,&(outside_addr.sin_port),2);

	my_send(browser_fd,buff,14,"init_from_browser");

	ev_io_init(browser_watcher,handle_from_browser,browser_fd,EV_READ);
	ev_io_start(my_loop,browser_watcher);
}

static void handle_from_browser(struct ev_loop*loop,struct ev_io*watcher,int revents)
{
	if (revents & EV_ERROR){
		printf("revent error at handle_from_browser\n");
		return;
	}

	CONN_INFO*info=(CONN_INFO*)watcher->data;
	int result;
	uint32_t len;
	char buff[MAXBUFF];
	result=recv(watcher->fd,buff+8,MAXBUFF,0);
	len=(uint32_t)result;
	if (result<=0){
		info_delete(&info_head[info->thread_id],info);
	}
	else{
		memcpy(buff,&(info->streamid),4);
		memcpy(buff+4,&len,4);
		my_send(entry_fd[info->thread_id],buff,8+len,"handle_from_browser");
	}
}

static void handle_from_entry(struct ev_loop*loop,struct ev_io*watcher,int revents)
{
	if (revents & EV_ERROR){
		printf("revents error at handle_from_entry\n");
		return;
	}

	char buff[MAXBUFF];
	CONN_INFO*ptr=(CONN_INFO*)watcher->data;
	uint32_t streamid,len;
	int result , thread_id=ptr->thread_id , temp;

	result=recv(entry_fd[thread_id],&streamid,4,0);
	ptr=info_search(&info_head[thread_id],streamid);

	//-----can not find this connection-----
	if (ptr==NULL){
		printf("cannot find streamid=%d , read this payload and ignore\n",streamid);
		recv(entry_fd[thread_id],&len,4,0);
		if (len<0 || len>2048){
			printf("payload length error , %d\n",len);
			exit(1);
		}
		else{
			for (result=0;result<len;){
				temp=recv(entry_fd[thread_id],buff,result,0);
				result+=temp;
			}
			return;
		}
	}

	recv(entry_fd[thread_id],&len,4,0);
	if (len<0||len>2048){
		printf("payload length error , %d\n",len);
		exit(1);
	}
	for (result=0;result<len;){
		temp=recv(entry_fd[thread_id],buff+result,len-result,0);
		result+=temp;
	}

	my_send(ptr->browser_fd,buff,len,"handle_from_entry");
}

void error_report(int kind,int num,int browser_fd)
{
	char type[10];
	if (kind==0)
		strcpy(type,"recv");
	else
		strcpy(type,"send");

	printf("%s error at initial the proxy connection , num=%d , browser_fd=%d\n",type,num,browser_fd);
	close(browser_fd);
}


uint32_t get_streamid(void)
{
	return streamid_master++;
}
uint32_t connection_distribute(uint32_t streamid)
{
	return streamid%THREAD_NUM;
}

CONN_INFO*info_init(int browser_fd,uint32_t streamid,uint32_t thread_id,struct ev_io*browser_watcher)
{
	CONN_INFO*info=(CONN_INFO*)malloc(sizeof(CONN_INFO));
	info->next=NULL;
	info->browser_fd=browser_fd;
	info->streamid=streamid;
	info->thread_id=thread_id;
	info->watcher=browser_watcher;
	return info;
}

void info_insert(CONN_INFO*head,CONN_INFO*tag)
{   
	CONN_INFO*walker;

	for (walker=head;walker->next!=NULL;walker=walker->next)//-----get the last node-----
		;

	walker->next=tag;
	tag->next=NULL;

	return;
}
void info_delete(CONN_INFO*head,CONN_INFO*tag)
{
	CONN_INFO*walker,*prev;
	int tag_streamid=tag->streamid;

	for (walker=head->next,prev=head;walker!=NULL;walker=walker->next){
		if (walker->streamid==tag_streamid){
			prev->next=walker->next;
			/*
			ev_io_stop(my_loop,walker->watcher);
			free(walker->watcher);
			close(walker->browser_fd);
			free(walker);*/
			return;
		}
		prev=walker;
	}
}                                                                                                                                                                                  
CONN_INFO*info_search(CONN_INFO*head,int streamid)
{
	CONN_INFO*walker;
	for (walker=head;walker!=NULL;walker=walker->next){
		if (walker->streamid==streamid)
			return walker;
	}
	return NULL;
}

void my_send(int fd,char*buff,int size,char func_name[])
{
	int result;
	result=send(fd,buff,size,0);
#ifdef debug
	if (result<size)
		printf("send not complete , need to send %d but only send %d\n",size,result);
	if (result<0)
		printf("send error at func %s , %s\n",func_name,strerror(errno));
#endif
}








