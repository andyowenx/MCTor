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
	uint32_t browser_fd;
	uint32_t streamid;
	uint32_t thread_id;
}CONN_INFO;

CONN_INFO thread_head[THREAD_NUM];

uint32_t streamid_master=0;
int exit_fd[THREAD_NUM];

struct ev_loop*thread_loop[THREAD_NUM];

SSL_CTX* InitServerCTX(void);
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile);
void ShowCerts(SSL* ssl);
void Servlet(SSL* ssl);

int server_init(int port);
int connect_init(char*outside);

void thread_func(int*id);
static void handle_from_middle(struct ev_loop*loop,struct ev_io*watcher,int revents);
static void read_outside(struct ev_loop*loop,struct ev_io*watcher,int revents);

CONN_INFO*info_init(int browser_fd,int streamid,int thread_id);
void info_insert(CONN_INFO*head,CONN_INFO*tag);
void info_delete(CONN_INFO*head,CONN_INFO*tag);
CONN_INFO*info_search(CONN_INFO*head,int streamid);

int main()
{
	//SSL_library_init();
	/*
	   if (  pthread_mutex_init(&lock,NULL) !=0){
	   printf("pthread mutex fail\n");
	   exit(1);
	   }
	 */
	signal(SIGPIPE,SIG_IGN);
	struct ev_io fd;
	pthread_t thread[THREAD_NUM];
	int i,thread_id[THREAD_NUM];


	for (i=0;i<THREAD_NUM;i++){
		thread_id[i]=i;
		thread_loop[i]=NULL;
		pthread_create(&thread[i],NULL,(void*)thread_func,(void*)&thread_id[i]);
	}

	for (i=0;i<THREAD_NUM;i++)
		pthread_join(thread[i],0);

	//my_loop=ev_default_loop(0);

	//ev_io_init(&fd,browser_connect_to_proxy,server_fd,EV_READ);
	//ev_io_start(my_loop,&fd);
	//ev_loop(my_loop,0);

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

	listen(server_fd,10);
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


static void read_outside(struct ev_loop*loop,struct ev_io*watcher,int revents)
{
	char buff[MAXBUFF];
	ssize_t result;
	uint32_t len;
	if (EV_ERROR & revents){
		printf("revents error at read browser\n");
		return;
	}

	CONN_INFO*info=(CONN_INFO*)watcher->data;
	result=recv(watcher->fd,buff,MAXBUFF,0);

	len=result;
	//-----end of connection-----
	if (result<=0){
		ev_io_stop(thread_loop[info->thread_id],watcher);
		if (watcher->fd)
			close(watcher->fd);
		info_delete(&thread_head[info->thread_id],info);
		free(watcher);
	}
	else{  //-----normal receive packet from browser-----
		send(exit_fd[info->thread_id],&(info->streamid),sizeof(uint32_t),0);		//-----stream id-----
		send(exit_fd[info->thread_id],&len,sizeof(uint32_t),0);		//-----offset-----
		send(exit_fd[info->thread_id],buff,len*sizeof(char),0);	//-----payload-----
	}
}

CONN_INFO*info_init(int browser_fd,int streamid,int thread_id)
{
	CONN_INFO*info=(CONN_INFO*)malloc(sizeof(CONN_INFO));
	info->next=NULL;
	info->browser_fd=browser_fd;
	info->streamid=streamid;
	info->thread_id=thread_id;
	return info;
}

void info_insert(CONN_INFO*head,CONN_INFO*tag)
{
	CONN_INFO*walker;
	if (head==NULL){
		head=tag;
		tag->next=NULL;
		return;
	}

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
	if (head->streamid==tag_streamid){
		prev=head;
		head=head->next;
		free(prev);
		return;
	}

	for (walker=head->next,prev=head;walker!=NULL;walker=walker->next){
		if (walker->streamid==tag_streamid){
			prev->next=walker->next;
			free(walker);
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

int connect_init(char*outside)
{
	int client_fd;
	struct sockaddr_in client_addr;
	struct timeval time_opt={0};
	char buff[MAXBUFF];
	int option=1;
	int port;
	
	bzero((char*)&client_addr,sizeof(client_addr));
	memcpy(&port,outside+4,2);

	client_addr.sin_family=AF_INET;
	client_addr.sin_port=htons( port  );
	memcpy(&client_addr.sin_addr.s_addr,outside,4);
	
	printf("connect to %s:%d\n",inet_ntoa(client_addr.sin_addr),client_addr.sin_port);

	if ( (client_fd=socket(AF_INET,SOCK_STREAM,0))  <0   ){
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

	if ( setsockopt(client_fd, SOL_SOCKET, SO_REUSEADDR, (uint *)&option, sizeof(option)) ==-1  ) {
		printf("setsocket error at client init\n");
		return -1; 
	}   
	
	if ( connect(client_fd,(struct sockaddr*)&client_addr,sizeof(client_addr)) <0  ){
		printf("connect error at client_init\n");
		return -1;
	}

	return client_fd;
}

void thread_func(int*id)
{

	exit_fd[*id]=server_init(EXIT_PORT+*id);

	thread_loop[*id]=ev_loop_new(0);
	struct ev_io*exit_watcher=(struct ev_io*)malloc(sizeof(struct ev_io));
	exit_watcher->data=(void*)id;

	ev_io_init(exit_watcher, handle_from_middle , exit_fd[*id], EV_READ);
	ev_io_start(thread_loop[*id],exit_watcher);

	ev_loop(thread_loop[*id],0);

	return;
}

static void handle_from_middle(struct ev_loop*loop,struct ev_io*watcher,int revents)
{
	if ( EV_ERROR &revents  ){
		printf("EV_ERROR at handle_from_mddle\n");
		return;
	}

	uint32_t streamid , payload_len;
	char buff[MAXBUFF];
	CONN_INFO*ptr;
	int*id=(int*)watcher->data;
	struct ev_io *outside_watcher;

	while (1){
		recv(exit_fd[*id],&streamid,sizeof(uint32_t),0);
		ptr=info_search(&thread_head[*id],streamid);
		//-----new connection incoming-----
		if (ptr==NULL){
			ptr=info_init(-1,streamid,*id);
			info_insert(&thread_head[*id],ptr);
			recv(exit_fd[*id],&payload_len,sizeof(uint32_t),0);
			recv(exit_fd[*id],buff,payload_len*sizeof(char),0);
			ptr->browser_fd=connect_init(buff);
			
			if (ptr->browser_fd==-1){
				info_delete(&thread_head[*id],ptr);

				send(exit_fd[*id],&streamid,sizeof(streamid),0);
				payload_len=10;
				send(exit_fd[*id],&payload_len,sizeof(payload_len),0);
				memcpy(buff,"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00", 10); //-----connect error message back to browser-----
				send(exit_fd[*id],buff,payload_len*sizeof(char),0);
				continue;
			}
			
			outside_watcher=(struct ev_io*)malloc(sizeof(struct ev_io));
			outside_watcher->data=(void*)ptr;
			ev_io_init(outside_watcher, read_outside , ptr->browser_fd , EV_READ);
			ev_io_start(thread_loop[*id],outside_watcher);
		}

		recv(exit_fd[*id],&payload_len,sizeof(uint32_t),0);
		recv(exit_fd[*id],buff,payload_len*sizeof(char),0);
		if (payload_len==0){
			send(ptr->browser_fd,buff,0,0);
			continue;
		}
		send(ptr->browser_fd,buff,payload_len*sizeof(char),0);

	}

	return;
}
