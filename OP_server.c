#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <ev.h>
#include <netdb.h>
#include "hidden_info.h"

typedef struct conn_info{
	struct conn_info*next;
	int browser_fd;
	uint32_t streamid;
	uint32_t thread_id;
	struct ev_io*watcher;
}CONN_INFO;

CONN_INFO thread_head[THREAD_NUM];
pthread_mutex_t lock;

uint32_t streamid_master=0;
int entry_fd[THREAD_NUM];

struct ev_loop *my_loop=NULL;

SSL_CTX* InitServerCTX(void);
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile);
void ShowCerts(SSL* ssl);
void Servlet(SSL* ssl);

int server_init(void);
static void browser_connect_to_proxy(struct ev_loop*loop,struct ev_io*watcher,int revents);
char* getOutsideAddr(int browser_fd);
void sock_auth_fail(int step,int kind);
uint32_t get_stream_id();
uint32_t connection_distribute(uint32_t streamid);
static void read_browser(struct ev_loop*loop,struct ev_io*watcher,int revents);
void total_send(int fd,char *buff, uint32_t len, char func_name[]);
void total_recv(int fd,char *buff , uint32_t len , char func_name[]);

void thread_func(int*id);

CONN_INFO*info_init(int browser_fd,int streamid,int thread_id);
void info_insert(CONN_INFO*head,CONN_INFO*tag);
void info_delete(CONN_INFO*head,CONN_INFO*tag);
CONN_INFO*info_search(CONN_INFO*head,int streamid);



int main()
{
	//SSL_library_init();
	
	/*
	if (pthread_mutex_init(&lock,NULL)!=0){
		printf("mutex lock init error\n");
		exit(1);
	}*/
	signal(SIGPIPE,SIG_IGN);
	int server_fd=server_init();
	struct ev_io fd;
	pthread_t thread[THREAD_NUM];
	int i,thread_id[THREAD_NUM];


	for (i=0;i<THREAD_NUM;i++){
		thread_id[i]=i;
		thread_head[i].browser_fd=-1;
		thread_head[i].streamid=-1;
		thread_head[i].thread_id=-1;
		thread_head[i].next=NULL;
		pthread_create(&thread[i],NULL,(void*)thread_func,(void*)&thread_id[i]);
	}


	my_loop=ev_default_loop(0);

	ev_io_init(&fd,browser_connect_to_proxy,server_fd,EV_READ);
	ev_io_start(my_loop,&fd);
	ev_loop(my_loop,0);

	/*
	//SSL_CTX *ctx;
	//ctx=InitServerCTX();
	//LoadCertificates(ctx,CA,KEY);
	while (1){
	printf("into accept\n");
	if (  (client_fd=accept(server_fd,  (struct sockaddr*)&client_addr,      &client_len)) <0){
	perror("accept error\n");
	exit(1);
	}
	//	SSL *ssl;
	//	ssl=SSL_new(ctx);
	//	SSL_set_fd(ssl,client_fd);
	//	Servlet(ssl);
	//	printf("ssl success\n");
	}
	close(server_fd);
	//SSL_CTX_free(ctx);
	//AES_KEY enc_key, dec_key;
	 */
	return 0;
}

/*
   CELL_QUEUE*get_queue_head(int thread_id)
   {
   return queue_head[thread_id];
   }

   CELL_QUEUE*queue_init(int buff_len)
   {
   CELL_QUEUE*cell;
   cell=(CELL_QUEUE*)malloc(sizeof(CELL_QUEUE));
   cell->content=(char*)malloc(buff_len*sizeof(char));
   return cell;
   }

   void queue_insert(CELL_QUEUE*head,char*str,int len)
   {
   CELL_QUEUE*p=queue_init(len);
   a

   }
 */

int server_init()
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
	server_addr.sin_port=htons(OP_PORT);


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

SSL_CTX* InitServerCTX(void)
{   const SSL_METHOD *method;
	SSL_CTX *ctx;

	OpenSSL_add_all_algorithms();		/* load & register all cryptos, etc. */
	SSL_load_error_strings();			/* load all error messages */
	method = SSLv23_server_method();		/* create new server-method instance */
	ctx = SSL_CTX_new(method);			/* create new context from method */
	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	/* set the local certificate from CertFile */
	if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* verify private key */
	if ( !SSL_CTX_check_private_key(ctx) )
	{
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
	char *line;

	cert = SSL_get_peer_certificate(ssl);	/* Get certificates (if available) */
	if ( cert != NULL )
	{
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
		X509_free(cert);
	}
	else
		printf("No certificates.\n");


	X509 *x509;
	BIO *i = BIO_new(BIO_s_file());
	BIO *o = BIO_new_fp(stdout,BIO_NOCLOSE);

	if(		(BIO_read_filename(i, CA) <= 0) ||
			((x509 = PEM_read_bio_X509_AUX(i, NULL, NULL, NULL)) == NULL)) {
		printf("cannot print CA\n");
	}
	else
		X509_print_ex(o, x509, XN_FLAG_COMPAT, X509_FLAG_COMPAT);
}

void Servlet(SSL* ssl)	/* Serve the connection -- threadable */
{   char buf[1024];
	char reply[1024];
	int sd, bytes;
	const char* HTMLecho="<html><body><pre>%s</pre></body></html>\n\n";

	if ( SSL_accept(ssl) == -1 )					/* do SSL-protocol accept */
		ERR_print_errors_fp(stderr);
	else
	{
		ShowCerts(ssl);								/* get any certificates */
		bytes = SSL_read(ssl, buf, sizeof(buf));	/* get request */
		if ( bytes > 0 )
		{
			buf[bytes] = 0;
			printf("Client msg: \"%s\"\n", buf);
			sprintf(reply, HTMLecho, buf);			/* construct reply */
			SSL_write(ssl, reply, strlen(reply));	/* send reply */
		}
		else
			ERR_print_errors_fp(stderr);
	}
	sd = SSL_get_fd(ssl);							/* get socket connection */
	SSL_free(ssl);									/* release SSL state */
	close(sd);										/* close connection */
}

static void browser_connect_to_proxy(struct ev_loop*loop,struct ev_io*watcher,int revents)
{
	int browser_fd  , connect_tag;
	uint32_t streamid ,payload_len;
	struct sockaddr_in browser_addr , entry_addr;
	int browser_len=sizeof(browser_addr)  ,result,temp;
	char *outside;
	char buff[MAXBUFF];
	struct ev_io*browser_watcher;

	if (revents&EV_ERROR){
		printf("error at browser_connect_to_proxy , revent error\n");
		return;
	}
	//-----accept the connection from browser-----
	if (  ( browser_fd=accept(watcher->fd, (struct sockaddr*)&browser_addr,&browser_len) )  <0 ){
		printf("error at browser_connect_to_proxy , accept error\n");
		return;
	}

	outside=getOutsideAddr(browser_fd);

	if (outside==NULL){
		printf("error happen , drop this connection\n");
		return;
	}


	payload_len=6;
	streamid=get_stream_id();
	connect_tag=connection_distribute(streamid);
	//-----send outside addr to exit node-----
	CONN_INFO*info=info_init(browser_fd,streamid,connect_tag);
	info_insert(&thread_head[connect_tag],info);

	memcpy(buff,&streamid,4);
	memcpy(buff+4,&payload_len,4);
	memcpy(buff+8,outside,6);
	
	total_send(entry_fd[connect_tag],buff,payload_len+8,"browser_connect_to_proxy");

	free(outside);

	browser_watcher=(struct ev_io*)malloc(sizeof(struct ev_io));
	browser_watcher->data=(void*)info;
	info->watcher=browser_watcher;
	ev_io_init(browser_watcher, read_browser, browser_fd,EV_READ);
	ev_io_start(my_loop,browser_watcher);
}


char*getOutsideAddr(int browser_fd)
{
	//-----set the socket option first-----
	struct timeval time_opt={0};
	struct sockaddr_in outside_addr;
	int option=1 , hostname_len ,result;
	char buff[MAXBUFF];
	char *return_str=(char*)malloc(7*sizeof(char));
	time_opt.tv_sec=2;
	time_opt.tv_usec=0;

#ifdef SO_NOSIGPIPE                                                                                             
	setsockopt(browser_fd, SOL_SOCKET, SO_NOSIGPIPE, &option, sizeof(option));
#endif


	if ( (setsockopt(browser_fd,SOL_SOCKET,SO_RCVTIMEO,(char*)&time_opt,sizeof(time_opt))  == -1)
			|| (    setsockopt(browser_fd,SOL_SOCKET,SO_SNDTIMEO,(char*)&time_opt,sizeof(time_opt))  ==-1)  ){
		printf("setsockopt error at getOutsideAddr\n");
		return NULL;
	}
	if ( setsockopt(browser_fd,SOL_SOCKET,SO_REUSEADDR,(uint*)&option,sizeof(option)) ==-1   ){
		printf("setsockopt reuse error at getOutsideAddr");
		return NULL;
	}
	//-----socket auth , step one-----
	if ( recv(browser_fd,buff,MAXBUFF,0) ==-1 ){
		sock_auth_fail(1,0);
		return NULL;
	}
	if ( send(browser_fd,"\x05\x00",2,0)==-1  ){
		sock_auth_fail(1,1);
		return NULL;
	}

	//-----socket auth , step two-----
	outside_addr.sin_family=AF_INET;
	
	total_recv(browser_fd,buff,4,"getOutsideAddr");
	if (buff[0]!=5	//socket5
			||buff[1]!=1){	//CONNECT
		buff[0]=5;
		buff[1]=7;	//connection not support
		buff[2]=0;	//end
		send(browser_fd,buff,4,0); //-----command not support-----
		return NULL;
	}
	if (buff[3]==1){  //-----IPv4-----
		total_recv(browser_fd,buff,4,"getOutsideAddr");
		memcpy(return_str,buff,4);
		memcpy(&outside_addr.sin_addr.s_addr,buff,4);

		total_recv(browser_fd,buff,2,"getOutsideAddr");
		memcpy(return_str+4,buff,2);
		memcpy(&outside_addr.sin_port,buff,2);

		printf("outside addr :  %s:%d\n",inet_ntoa(outside_addr.sin_addr),ntohs(outside_addr.sin_port));
	}
	else if (buff[3]==3){ //-----query with domain name-----
		struct hostent *hp;
		total_recv(browser_fd,buff,1,"getOutsideAddr");
		hostname_len=buff[0];
		buff[hostname_len]=0;
		total_recv(browser_fd,buff,hostname_len,"getOutsideAddr");
		hp=gethostbyname(buff);
		printf("outside domain : %s\n",buff);
		if (buff==NULL){
			printf("domain name is NULL at getOutsideAddr\n");
			return NULL;
		}
		if (hp->h_addrtype!=AF_INET){
			printf("struct hostent->h_addrtype error at getOutsideAddr\n");
			return NULL;
		}
		if (*(hp->h_addr_list)==NULL){
			printf("struct hostent->h_addr_list errpr at getOutsideAddr\n");
			return NULL;
		}
		memcpy( return_str,*(hp->h_addr_list),4);

		total_recv(browser_fd,buff,2,"getOutsideAddr");
		memcpy( return_str+4,buff,2);

	}
	else{   //-----command not support-----
		buff[0]=5;
		buff[1]=8;
		buff[2]=0;
		if ( send(browser_fd,buff,4,0) ==-1){
			sock_auth_fail(2,1);
			return NULL;
		}
	}
	return_str[6]=0;

	return return_str;
}

void sock_auth_fail(int step,int kind)
{
	if (kind==0) //-----recv fail-----
		printf("recv socket auth fail at step %d at getOutsideAddr\n",step);
	else //-----send fail-----
		printf("send socket auth fail at step %d at getOutsideAddr\n",step);
}
uint32_t get_stream_id(void)
{
	return streamid_master++;
}

uint32_t connection_distribute(uint32_t streamid)
{
	return streamid%THREAD_NUM;
}

static void read_browser(struct ev_loop*loop,struct ev_io*watcher,int revents)
{
	char buff[MAXBUFF];
	uint32_t len,temp,result;
	if (EV_ERROR & revents){
		printf("revents error at read browser\n");
		return;
	}

	CONN_INFO*info=(CONN_INFO*)watcher->data;


	//-----the first eight byte is stream id and payload length-----
	result=recv(watcher->fd,buff+8,MAXRECV,0);


	len=result;

	memcpy(buff,& (info->streamid),4);
	memcpy(buff+4,&len,4);

	//-----end of connection-----
	if (result<=0){
		printf("close fd=%d , streamid=%d\n",info->browser_fd,info->streamid);
		//ev_io_stop(my_loop,watcher);
		info_delete(&thread_head[info->thread_id],info);
		//if (watcher->fd)
		//	close(watcher->fd);
		//free(watcher);
	}
	else{  //-----normal receive packet from browser-----
		//printf("send to stream id : %d , len = %d\n",info->streamid,len);
		total_send(entry_fd[info->thread_id],buff,len+8,"read_browser");
		printf("send to entry ok , streamid=%d , len=%d\n",info->streamid,len+8);
	}
}

CONN_INFO*info_init(int browser_fd,int streamid,int thread_id)
{
	CONN_INFO*info=(CONN_INFO*)malloc(sizeof(CONN_INFO));
	info->next=NULL;
	info->browser_fd=browser_fd;
	info->streamid=streamid;
	info->thread_id=thread_id;
	info->watcher=NULL;
	return info;
}

void info_insert(CONN_INFO*head,CONN_INFO*tag)
{	
	//pthread_mutex_lock(&lock);
	CONN_INFO*walker;

	for (walker=head;walker->next!=NULL;walker=walker->next)//-----get the last node-----
		;

	walker->next=tag;
	tag->next=NULL;
	//pthread_mutex_unlock(&lock);

	return;
}
void info_delete(CONN_INFO*head,CONN_INFO*tag)
{
	//pthread_mutex_lock(&lock);
	CONN_INFO*walker,*prev;
	int tag_streamid=tag->streamid;

	for (walker=head->next,prev=head;walker!=NULL;walker=walker->next){
		if (walker->streamid==tag_streamid){
			prev->next=walker->next;
			ev_io_stop(my_loop,walker->watcher);
			free(walker->watcher);
			close(walker->browser_fd);
			free(walker);
			return;
		}
		prev=walker;
	}
	//pthread_mutex_unlock(&lock);
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




void thread_func(int*id)
{
	struct sockaddr_in entry_addr;
	struct ev_io*entry_watcher,*browser_watcher;
	uint32_t streamid , payload_len;
	char buff[MAXBUFF];
	int i,receive_num,temp, result;
	CONN_INFO*ptr;

	if ( (entry_fd[*id]=socket(AF_INET,SOCK_STREAM,0)) <0 ){
		printf("open socket error at thread %d\n",*id);
		return;
	}

	bzero((char*)&entry_addr,sizeof(entry_addr));
	entry_addr.sin_family=AF_INET;
	entry_addr.sin_port=htons(ENTRY_PORT+*id);
	inet_aton(ENTRY_IP,&entry_addr.sin_addr);

	if ( connect(entry_fd[*id],(struct sockaddr*)&entry_addr,sizeof(entry_addr)) <0 ){
		printf("connect error at thread %d\n",*id);
		return;
	}
	while (1){
		total_recv(entry_fd[*id],buff,4,"thread_func");
		memcpy(&streamid,buff,4);
		total_recv(entry_fd[*id],buff,4,"thread_func");
		memcpy(&payload_len,buff,4);
		if(payload_len < 0 || payload_len> 8192 ){
			//printf("recv EOF from entry , close streamid=%d\n",streamid);
			//info_delete(&thread_head[*id],info_search(&thread_head[*id],streamid));
			printf("recv error here ,streamid=%d  , payload_len=%d\n",streamid,payload_len);
			continue;
		}
		ptr=info_search(&thread_head[*id],streamid);


		if (ptr==NULL){
			printf("cannot find ptr which streamid=%d , payload_len=%d\n",streamid,payload_len);
			if (payload_len <8192 && payload_len >=0 )
				total_recv(entry_fd[*id],buff,payload_len,"thread_func");
			continue;
		}

		total_recv(entry_fd[*id],buff,payload_len,"thread_func");

		printf("recv from entry ok , streamid=%d , len=%d\n",streamid,payload_len+8);

		total_send(ptr->browser_fd,buff,payload_len,"thread_func");
	}
	return;
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
