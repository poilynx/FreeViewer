#include "common.h"
#include "tunnel.h"
#include "sslutil.h"

struct tunnel_listener_st {
	struct evconnlistener *listener;
	uint16_t bindport;
	struct ssl_ctx_st *sslctx;
	tunnel_listen_cb listen_cb;
	void * arg;
};

enum tunnel_status_en {
	TS_CONNECTING,
	TS_VERIFYING,
	TS_ACCEPTING,
	TS_CLEANING
};



struct tunnel_st {
	struct bufferevent *bev;
	char listener_name[MAX_NAME_LENGTH+1];
	tunnel_ctx_t *tctx;
};

struct tunnel_ctx_st {
	enum tunnel_status_en status;
	union {
		struct {
			tunnel_connect_cb connect_cb;
			tunnel_verify_cb verify_cb;
			int challenging;
			char name[MAX_NAME_LENGTH+1];
			//char passwd[MAX_PASSWD_LENGTH+1];
		} active;

		struct {
			tunnel_listener_t *tlistener;
		} passive;

		struct {

		} open;
	};
	tunnel_t *tun;
	void *arg;
};

static void passive_event_cb(struct bufferevent *bev, short events, void *arg) {
	printf("traverse_event_cb events = %hx\n", events);
	if(events & BEV_EVENT_ERROR) {
		tunnel_ctx_t *ctx = (tunnel_ctx_t*) arg;
		long ev_err = bufferevent_get_openssl_error(bev);
		if(errno) {
			printf("c error: %s\n", strerror(errno));
		} else if(ev_err) {
			printf("ssl error: %s\n", ERR_reason_error_string(ev_err));
		}
		free(ctx->tun);
		free(ctx);
		bufferevent_free(bev);
	} 
	if(events & BEV_EVENT_CONNECTED) {
		printf("ctx = %p\n", arg);
		//SSL *ssl = (SSL*)ctx;
		printf("ssl connected\n");
		//show_certs_info(ssl); ///
	}
}

static void passive_read_cb(struct bufferevent *bev, void *arg)
{
	struct evbuffer *in = bufferevent_get_input(bev);
	tunnel_ctx_t *tctx = (tunnel_ctx_t *) arg;

	char passwd[ACCESS_PASSWD_MAX_LENGTH+1];
	//char name[MAX_NAME_LENGTH+1];
	unsigned char *p = evbuffer_pullup(in, -1);
	int i, len = -1, size = evbuffer_get_length(in);
	if(size > MAX_PASSWD_LENGTH+1) {
		size = MAX_PASSWD_LENGTH+1;
	}
	for(i=0; i<size; i++) { // find '\n' in message recved
		if(p[i] == '\n') {
			len = i;
			break;
		}
	}
	if(len > 0) {
		memcpy(passwd, p, len);
		passwd[len] = '\0';
		evbuffer_drain(in, len + 1); // include `\n'
		tctx->passive.tlistener->listen_cb(tctx->tun, passwd, tctx->arg);
	} else if (size == MAX_PASSWD_LENGTH) { //password recved too long
		bufferevent_free(bev);
		free(tctx->tun);
		free(tctx);
	}
}

/*
int verify_callback(int ok, X509_STORE_CTX *store)
{
	char data[256];
	printf("verify callback\n");
	if (ok)
	{
		fprintf(stderr, "verify_callback\n{\n");
		X509 *cert = X509_STORE_CTX_get_current_cert(store);
		int  depth = X509_STORE_CTX_get_error_depth(store);
		int  err = X509_STORE_CTX_get_error(store);
		//SSL_CTX_set_ex_data
		SSL *ssl = X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx());
		SSL_get_app_data(ssl);


		fprintf(stderr, "certificate at depth: %i\n", depth);
		memset(data, 0, sizeof(data));
		X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
		fprintf(stderr, "issuer = %s\n", data);
		X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
		fprintf(stderr, "subject = %s\n", data);
		fprintf(stderr, "error status:  %i:%s\n}\n", err, X509_verify_cert_error_string(err));
	}
	//return ok;
	return ok;
}
*/
static void listen_error_cb(struct evconnlistener *serv, void *arg) {

}

static void listener_accept_cb(struct evconnlistener *serv, int sock, struct sockaddr *sa,
		int sa_len, void *arg)
{
	printf("listener_accept_cb sock = %d\n", sock);
	struct event_base *evbase;
	struct bufferevent *bev;

	tunnel_listener_t *tlistener = (tunnel_listener_t*) arg;
	
	tunnel_ctx_t *tctx = malloc(sizeof(tunnel_ctx_t));
	if(tctx == NULL) {
		perror("malloc");
		exit(-1);
	}
	tctx->status = TS_ACCEPTING;
	tctx->passive.tlistener = tlistener;

	tunnel_t *tun = malloc(sizeof(tunnel_t));
	if(tun == NULL) {
		perror("malloc");
		exit(-1);
	}

	tun->tctx = tctx;
	tctx->tun = tun;



	SSL *ssl = SSL_new(tlistener->sslctx);
	/*
	char data[256];
	X509 *cert = SSL_get_certificate(ssl);
	X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
	printf("data = %s\n", data);
	assert(ssl);
	*/


	assert(sslutil_ssl_get_local_CN(ssl, tun->listener_name, sizeof(tun->listener_name)) == 0);

	evbase = evconnlistener_get_base(serv);
	assert(evbase);

	bev = bufferevent_openssl_socket_new(evbase, sock, ssl,
			BUFFEREVENT_SSL_ACCEPTING,
			BEV_OPT_CLOSE_ON_FREE);
	assert(bev);
	tun->bev = bev;

	bufferevent_enable(bev, EV_READ);
	bufferevent_setcb(bev,passive_read_cb, NULL, passive_event_cb, tctx);


	printf("over listener_accept_cb\n");
}

tunnel_listener_t *tunnel_listener_new(struct event_base *evbase, uint16_t port,
		struct ssl_ctx_st *sslctx, tunnel_listen_cb listen_cb, void *arg) {
	struct evconnlistener *listener;
	struct sockaddr_in sin;
	assert(evbase && port > 0 && sslctx && listen_cb);
	tunnel_listener_t *tlistener = malloc(sizeof(tunnel_listener_t));

	printf("tunnel_listener_new port = %hu\n", port);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = INADDR_ANY;

	/* create listenning socket */
	listener = evconnlistener_new_bind(
			evbase, listener_accept_cb, (void *)tlistener,
			LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE | LEV_OPT_REUSEABLE_PORT, 1024,
			(struct sockaddr *)&sin, sizeof(sin));
	
	if(listener == NULL) {
		printf("evconnlistener_new_bind error\n");
		exit(-1);
	}
	tlistener->listener = listener;
	tlistener->bindport = port;
	tlistener->listen_cb = listen_cb;
	tlistener->sslctx = sslctx;
	tlistener->arg = arg;
	//evconnlistener_enable(listener);
	evconnlistener_set_error_cb(listener, listen_error_cb);

	return tlistener;
}


void tunnel_listener_free(tunnel_listener_t *tlistener) {
	evconnlistener_free(tlistener->listener);
	SSL_CTX_free(tlistener->sslctx);
	free(tlistener);
}

/*
static void punch_write_cb(struct bufferevent *bev, void *arg) {
	printf("punch_write_cb\n");
}
*/

static void punch_event_cb(struct bufferevent *bev, short events, void *arg) {
	printf("punch_event_cb\n");
	/* Connected || timeout || error */
	bufferevent_free(bev);

}
#define PUNCH_CONNECT_TIMEOUT 2
void tunnel_listener_punch(tunnel_listener_t *tlistener, const struct sockaddr_in *sa) {
	struct event_base *base = evconnlistener_get_base(tlistener->listener);
	assert(base);
	struct sockaddr_in bindaddr;
	int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert(sockfd);

	evutil_make_socket_nonblocking(sockfd);
	evutil_make_listen_socket_reuseable(sockfd);
	evutil_make_listen_socket_reuseable_port(sockfd);

	bzero(&bindaddr, sizeof(bindaddr));
	bindaddr.sin_family = AF_INET;
	bindaddr.sin_port = htons(tlistener->bindport);
	bindaddr.sin_addr.s_addr = INADDR_ANY;
	//bindaddr.sin_addr.s_addr = sa->sin_addr.s_addr;

	if(bind(sockfd, (const struct sockaddr*)&bindaddr, sizeof(bindaddr)) != 0) {
		perror("bind");
		exit(-1);
	}
	
	struct bufferevent *bev = bufferevent_socket_new(base, sockfd, BEV_OPT_CLOSE_ON_FREE);
	assert(sa->sin_family == AF_INET);
	if(bufferevent_socket_connect(bev, (struct sockaddr*)sa, sizeof(struct sockaddr_in))) {
		perror("bufferevent_socket_connect: ");
		exit(1);
	}
	bufferevent_enable(bev, EV_WRITE);
	bufferevent_setcb(bev, NULL, NULL, punch_event_cb, NULL);
	bufferevent_settimeout(bev, 0, PUNCH_CONNECT_TIMEOUT);
	
}


void tunnel_accept(tunnel_t *tun) {
	char buf[] = "0 OK\n";
	assert(tun);
	assert(tun->tctx && tun->tctx->status == TS_ACCEPTING);
	free(tun->tctx);
	tun->tctx = NULL;
	bufferevent_write(tun->bev, buf, sizeof(buf) - 1);
	bufferevent_setcb(tun->bev, NULL, NULL, NULL, NULL);
}

/* reply reject message but do not close bev */

void tunnel_reject(tunnel_t *tun, uint8_t status) {
	char buf[256];
	assert(tun);
	assert(status >= 1 && status <= 9);
	assert(tun->tctx && tun->tctx->status == TS_ACCEPTING);
	char *str;
	switch(status) {
		case TVS_Busy:
			str = "Busy";
			break;
		case TVS_Forbidden:
			str = "Forbiddena";
			break;
		case TVS_PermissionDenied:
			str = "PermissionDenied";
			break;
		case TVS_Unknow:
			str = "Unknow";
			break;
		default:
			str = "Undefined";
			break;
			
	}
	sprintf(buf, "%hhu %s\n", status, str);
	bufferevent_write(tun->bev, buf, strlen(buf));
}


const char *tunnel_get_listener_name(tunnel_t *tun) {
	return tun->listener_name;
}

#if 0
static int active_verify_cb(int ok, X509_STORE_CTX *store)
{
        if (ok)
        {
                int  depth = X509_STORE_CTX_get_error_depth(store);
                //int  err = X509_STORE_CTX_get_error(store);
		if(depth == 0) {
			char data[256];
			char cname[MAX_NAME_LENGTH + 1];
			cname[sizeof(cname) - 1] = '\0';

			memset(data, 0, sizeof(data));

			X509 *cert = X509_STORE_CTX_get_current_cert(store);

			SSL *ssl = X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx());
			tunnel_ctx_t * conn_ctx = SSL_get_app_data(ssl);

			X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
			printf("\tIssuer = %s\n", data);
			X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
			printf("\tSubject = %s\n", data);

			sslutil_ssl_get_peer_CN(ssl, cname, sizeof(cname));
			if(strcmp(cname, conn_ctx->active.name) != 0) {
				puts("m1");
				return 0;
			}

			/*
			ASN1_INTEGER *aint = X509_get_serialNumber(cert);
			for(int i=0;i<aint->length;i++) {
				printf("%hhX:", aint->data[i]);
			}
			putchar('\n');
			*/
		}

		/*
                printf("Certificate at depth: %i\n", depth);
                memset(data, 0, sizeof(data));
                X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
                printf("\tIssuer = %s\n", data);
                X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
                printf("\tSubject = %s\n", data);
                printf("\terror status: %i:%s\n", err, X509_verify_cert_error_string(err));

		printf("\tSerial number: ");
		*/
		
        }
        return ok; 
}
#endif


static void active_event_cb(struct bufferevent *bev, short events, void *arg) {
	printf("conn_event_cb events = %hx\n", events);
	register tunnel_ctx_t *ctx = (tunnel_ctx_t*) arg;
	if(events & BEV_EVENT_ERROR) {
		long ev_err = bufferevent_get_openssl_error(bev);
		if(ev_err) {
			printf("ssl error: %s\n", ERR_reason_error_string(ev_err));
			ctx->active.connect_cb(NULL, CONNECT_ERR_SSL, ctx->arg);
		} else {
			ctx->active.connect_cb(NULL, CONNECT_ERR_UNREACHED, ctx->arg);
		}
		free(ctx);
		bufferevent_free(bev);
		
	}
	if(events & BEV_EVENT_CONNECTED) {
		printf("connected\n");
		assert(ctx->status == TS_CONNECTING);
		ctx->status = TS_VERIFYING;
		ctx->active.challenging = 0;

		ctx->active.connect_cb(ctx->tun, CONNECT_ERR_SUCCESS, ctx->arg);
	}
}

static void active_read_cb(struct bufferevent *bev, void *arg) {
	printf("conn_read_cb\n");
	
	register tunnel_ctx_t *ctx = (tunnel_ctx_t*) arg;
	if(ctx->active.challenging == 1) {
		unsigned char buf[32];
		struct evbuffer *in = bufferevent_get_input(bev);
		unsigned char * line = evbuffer_pullup(in, -1);
		int i, len = -1,
		    size = evbuffer_get_length(in) < sizeof(buf) - 1
			    ? evbuffer_get_length(in)
			    : sizeof(buf) - 1;

		buf[sizeof(buf) - 1] = '\0'; /* Secure */

		for(i=0; i<size; i++) {
			if(line[i] == '\n') {
				len = i;
				break;
			}
		}
		if(len == -1) {
			if(evbuffer_get_length(in) >= sizeof(buf)-1) {
				/* data error */
				ctx->active.verify_cb(ctx->tun, 9, ctx->arg);
				goto cleanup;
			} else {
				return;
			}
		}
		memcpy(buf, line, len);
		buf[len] = '\0';
		evbuffer_drain(in, len + 1);

		if( ! (buf[0] >= '0' && buf[0] <= '9' && buf[1] == ' ' && buf[2] != ' ')) {
			ctx->active.verify_cb(ctx->tun, 9, ctx->arg);
			goto cleanup;
		}

		unsigned int status_code = buf[0] - '0';
		char *status_string = (char *)buf + 2;

		printf("Remote message: %d %s\n",status_code, status_string);
		if(status_code != 0) {
			ctx->active.verify_cb(ctx->tun, status_code, ctx->arg);
			goto cleanup;
		}
		

		tunnel_verify_cb cb = ctx->active.verify_cb;;
		ctx->tun->tctx = NULL;
		free(ctx);

		bufferevent_setcb(bev, NULL, NULL, NULL, NULL);
		bufferevent_disable(bev, EV_READ | EV_WRITE);

		cb(ctx->tun, 0, ctx->arg);
		
	} else {
		printf("passive is crazy");
		abort();
		/* Error data*/
	}


	return;
cleanup:;
	ctx->status = TS_CLEANING; //protocol error
	//bufferevent_setcb(bev, NULL, pub_write_cb, NULL, NULL);
	//bufferevent_disable(bev, EV_READ);
}

static void pub_write_cb(struct bufferevent *bev, void *arg) {
	printf("conn_write_cb\n");
	//register tunnel_ctx_t *ctx = (tunnel_ctx_t*) arg;
	struct evbuffer *out = bufferevent_get_output(bev);
	if(evbuffer_get_length(out) == 0) {
		 bufferevent_free(bev);
	}
	
}

void tunnel_close(tunnel_t *tun) {
	assert(tun);
	bufferevent_setcb(tun->bev, NULL, pub_write_cb, NULL, NULL);
	if(tun->tctx) free(tun->tctx);
	free(tun);
	//event_base_loop(bufferevent_get_base(tun->bev), EVLOOP_ONCE);//TODO:
}

tunnel_t* tunnel_connect(struct event_base *evbase, const struct sockaddr_in *addr, uint16_t bindport, const char *name,
		const struct ssl_ctx_st *sslctx, tunnel_connect_cb connect_cb, tunnel_verify_cb verify_cb, void *arg) {
	struct bufferevent *bev;
	struct sockaddr_in bindaddr;
	//struct sockaddr_in peeraddr;
	int sock;
	SSL *ssl;

	memset(&bindaddr, 0, sizeof(bindaddr));
	bindaddr.sin_family = AF_INET;
	bindaddr.sin_port = htons(bindport);
	bindaddr.sin_addr.s_addr = INADDR_ANY;


	/* Check password */
	/*
	if(strlen(passwd) > ACCESS_PASSWD_MAX_LENGTH || *passwd == '\0') {
		return NULL;
	}
	*/

	/* Alloc and initialize tunnel struct */
	tunnel_t *tun = malloc(sizeof(tunnel_t));
	memset(tun, 0, sizeof(tunnel_t));

	/* Alloc and initialize tunnel context */
	tunnel_ctx_t *conn_ctx = malloc(sizeof(tunnel_ctx_t));
	memset(conn_ctx, 0, sizeof(tunnel_ctx_t));
	conn_ctx->status = TS_CONNECTING;
	strcpy(conn_ctx->active.name, name); /* FIXME: danger */
	//strcpy(conn_ctx->active.passwd, passwd); /* FIXME: danger */
	conn_ctx->active.connect_cb = connect_cb;
	conn_ctx->active.verify_cb = verify_cb;
	conn_ctx->arg = arg;

	/* link to each other */
	conn_ctx->tun = tun;
	tun->tctx = conn_ctx;

	/* Create a binding socket for connection */
	sock = socket(AF_INET, SOCK_STREAM, 0);
	evutil_make_listen_socket_reuseable_port(sock);
	evutil_make_listen_socket_reuseable_port(sock);

	if(bind(sock, (const struct sockaddr*)&bindaddr, sizeof(bindaddr)) != 0) {
		perror("bind");
		free(conn_ctx);
		evutil_closesocket(sock);
		return NULL;
	}

	ssl = SSL_new((struct ssl_ctx_st *)sslctx);
	SSL_set_app_data(ssl, conn_ctx);
	
	/* Create connecting bufferevent */
	bev = bufferevent_openssl_socket_new(
			evbase,
			sock,
			ssl,
			BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE /*|  BEV_OPT_DEFER_CALLBACKS*/);
	if(bev == NULL) {
		evutil_closesocket(sock);
		free(conn_ctx);
		printf("bufferevent_openssl_socket_new: %ld\n", bufferevent_get_openssl_error(bev));
		exit(-1);
	}

	/* assign bev for tunnel struct */
	tun->bev = bev;

	/* Connect */
	int ret = bufferevent_socket_connect(bev, (struct sockaddr*)addr, sizeof(struct sockaddr_in));
	printf("ret = %d\n", ret);

	bufferevent_enable(bev, EV_READ);
	bufferevent_setcb(bev, active_read_cb, NULL, active_event_cb, conn_ctx);

	bufferevent_settimeout(bev, 0, 5);

	return tun;
}


int tunnel_verify(tunnel_t *tun, const char *passwd) {
	assert(tun && passwd);
	size_t passwd_len = strlen(passwd);
	assert(passwd_len <= MAX_PASSWD_LENGTH);
	assert(tun->tctx && tun->tctx->status == TS_VERIFYING);
	
	if(tun->tctx->active.challenging == 0) {
		char nl = '\n';
		bufferevent_write(tun->bev, passwd, passwd_len);
		bufferevent_write(tun->bev, &nl, sizeof(nl));
		tun->tctx->active.challenging = 1;
		//tun->tctx->active.challenged = 1;
		return 0;
	} else {
		return -1;
	}
}


struct bufferevent *tunnel_get_bufferevent(tunnel_t *tun) {
	assert(tun);
	return tun->bev;
}
