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

typedef struct cell_queue{
	struct cell_queue*next;
	char*content;
}CELL_QUEUE;

CELL_QUEUE*queue_head=NULL;
int streamid_master=0;


int server_init(void);
SSL_CTX* InitServerCTX(void);
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile);
void ShowCerts(SSL* ssl);
void Servlet(SSL* ssl);
static void browser_connect_to_proxy(struct ev_loop*loop,struct ev_io*watcher,int revents);
void getOutsideAddr(int browser_fd,struct sockaddr_in*outside_addr);
void sock_auth_fail(int step,int kind);
int get_stream_id();
static void second_handle(struct ev_loop*loop,struct ev_io*watcher,int revents);
void thread_func(int id);

int main()
{
	//SSL_library_init();
	signal(SIGPIPE,SIG_IGN);
	int server_fd=server_init();
	struct ev_loop *my_loop=NULL;
	struct ev_io fd;
	pthread_t thread[THREAD_NUM];
	int i;

	for (i=0;i<THREAD_NUM;i++)
		pthread_create(&thread[i],NULL,(void*)thread_func,(void*)&i);

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

static void browser_connect_to_proxy(struct ev_loop*loop,struct ev_io*watcher,int revents)
{
	int browser_fd , streamid;
	struct sockaddr_in browser_addr , outside_addr , entry_addr;
	int browser_len=sizeof(browser_addr);
	if (revents&EV_ERROR){
		printf("error at browser_connect_to_proxy , revent error\n");
		return;
	}
	//-----accept the connection from browser-----
	if (  ( browser_fd=accept(watcher->fd, (struct sockaddr*)&browser_addr,&browser_len) )  <0 ){
		printf("error at browser_connect_to_proxy , accept error\n");
		return;
	}

	getOutsideAddr(browser_fd,&outside_addr);

	streamid=get_stream_id();

	//-----send outside addr to exit-----
	
}


void getOutsideAddr(int browser_fd,struct sockaddr_in*outside_addr)
{
	//-----set the socket option first-----
	struct timeval time_opt={0};
	int option=1 , outside_len , hostname_len;
	char buff[MAXBUFF];
	time_opt.tv_sec=2;
	time_opt.tv_usec=0;
	if ( (setsockopt(browser_fd,SOL_SOCKET,SO_RCVTIMEO,(char*)&time_opt,sizeof(time_opt))  == -1)
			|| (    setsockopt(browser_fd,SOL_SOCKET,SO_SNDTIMEO,(char*)&time_opt,sizeof(time_opt))  ==-1)  ){
		printf("setsockopt error at getOutsideAddr\n");
		return;
	}
	if ( setsockopt(browser_fd,SOL_SOCKET,SO_REUSEADDR,(uint*)&option,sizeof(option)) ==-1   ){
		printf("setsockopt reuse error at getOutsideAddr");
		return;
	}
	//-----socket auth , step one-----
	if ( recv(browser_fd,buff,MAXBUFF,0) ==-1 ){
		sock_auth_fail(1,0);
		return;
	}
	if ( send(browser_fd,"\x05\x00",2,0)==-1  ){
		sock_auth_fail(1,1);
		return;
	}

	//-----socket auth , step two-----
	if ( recv(browser_fd,buff,4,0)==-1){
		sock_auth_fail(2,0);
		return;
	}
	if (buff[0]==5	//socket5
			||buff[1]==1){	//CONNECT
		buff[0]=5;
		buff[1]=7;	//connection not support
		buff[2]=0;	//end
		send(browser_fd,buff,4,0); //-----command not support-----
		return;
	}
	if (buff[3]==1){  //-----IPv4-----
		bzero((char*)outside_addr,sizeof(outside_addr));
		outside_addr->sin_family=AF_INET;
		if ( recv(browser_fd,buff,4,0) ==-1){
			sock_auth_fail(2,0);
			return;
		}
		memcpy(&(outside_addr->sin_addr.s_addr),buff,4);
		if (  recv(browser_fd,buff,2,0) ==-1){
			sock_auth_fail(2,0);
			return;
		}
		memcpy(&(outside_addr->sin_port),buff,2);

		printf("outside addr :  %s:%d\n",inet_ntoa(outside_addr->sin_addr),htons(outside_addr->sin_port));
	}
	else if (buff[3]==3){ //-----query with domain name-----
		struct hostent *hp;
		bzero((char*)outside_addr,sizeof(outside_addr));
		outside_addr->sin_family=AF_INET;
		if (  recv(browser_fd,buff,1,0) ==-1){
			sock_auth_fail(2,0);
			return;
		}
		hostname_len=buff[0];
		buff[hostname_len]=0;
		if (  recv(browser_fd,buff,hostname_len,0) ==-1){
			sock_auth_fail(2,0);
			return;
		}
		hp=gethostbyname(buff);
		printf("outside domain : %s\n",buff);
		if (buff==NULL){
			printf("domain name is NULL at getOutsideAddr\n");
			return;
		}
		if (hp->h_addrtype!=AF_INET){
			printf("struct hostent->h_addrtype error at getOutsideAddr\n");
			return;
		}
		if (*(hp->h_addr_list)==NULL){
			printf("struct hostent->h_addr_list errpr at getOutsideAddr\n");
			return;
		}
		memcpy(&(outside_addr->sin_addr.s_addr),*(hp->h_addr_list),4);
		if (  recv(browser_fd,buff,2,0) ==-1){
			sock_auth_fail(2,0);
			return;
		}
		memcpy(&(outside_addr->sin_port),buff,2);

	}
	else{   //-----command not support-----
		buff[0]=5;
		buff[1]=7;
		buff[2]=0;
		if ( send(browser_fd,buff,4,0) ==-1){
			sock_auth_fail(2,1);
			return;
		}
	}
	return;
}

void sock_auth_fail(int step,int kind)
{
	if (kind==0) //-----recv fail-----
		printf("recv socket auth fail at step %d at getOutsideAddr\n",step);
	else //-----send fail-----
		printf("send socket auth fail at step %d at getOutsideAddr\n",step);
}
int get_stream_id(void)
{
	return streamid_master++;
}
static void second_handle(struct ev_loop*loop,struct ev_io*watcher,int revents)
{
}
void thread_func(int id)
{
	int entry_fd;
	struct sockaddr_in entry_addr;
	
	if ( (entry_fd=socket(AF_INET,SOCK_STREAM,0)) <0 ){
		printf("open socket error at thread %d\n",id);
		return;
	}

	bzero((char*)&entry_addr,sizeof(entry_addr));
	entry_addr.sin_family=AF_INET;
	entry_addr.sin_port=ENTRY_PORT+id;
	inet_aton(ENTRY_IP,&entry_addr.sin_addr);

	if ( connect(entry_fd,(struct sockaddr*)&entry_addr,sizeof(entry_addr)) <0 ){
		printf("connect error at thread %d\n",id);
		return;
	}

}
