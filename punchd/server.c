#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <event.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>

#include "ctx.h"
#include "server.h"

static int verify_callback(int ok, X509_STORE_CTX *store)
{
        char data[256];
        if (ok)
        {
                X509 *cert = X509_STORE_CTX_get_current_cert(store);
                int  depth = X509_STORE_CTX_get_error_depth(store);
                int  err = X509_STORE_CTX_get_error(store);

                printf("Certificate at depth: %i\n", depth);
                memset(data, 0, sizeof(data));
                X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
                printf("\tIssuer = %s\n", data);
                X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
                printf("\tSubject = %s\n", data);
                printf("\terror status: %i:%s\n", err, X509_verify_cert_error_string(err));

		printf("\tSerial number: ");
		ASN1_INTEGER *aint = X509_get_serialNumber(cert);

		for(int i=0;i<aint->length;i++) {
			printf("%hhX:", aint->data[i]);
		}
		putchar('\n');
        }
        return ok; 
}

SSL_CTX* server_ssl_ctx_init(const char *cafile, int depth, const char *keyfile, const char *certfile) {
	SSL_CTX *ctx;
	assert((keyfile && certfile) || (!keyfile && !certfile));

	SSL_load_error_strings();
	SSL_library_init();

	assert(RAND_poll());

	ctx = SSL_CTX_new(SSLv23_server_method());
	assert(ctx);

	if(cafile) {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
		if(SSL_CTX_load_verify_locations(ctx, cafile, NULL)  <= 0) {
			fprintf(stdout, "SSL_CTX_load_verify_locations:\n");
			ERR_print_errors_fp(stderr);
			exit(-1);
		}
	}

	if(certfile) {
		if (! SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM) ||
				! SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM)) {
			ERR_print_errors_fp(stderr);
			exit(-1);
		}
	}


	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
	return ctx;

}

static void accept_cb(struct evconnlistener *serv, int sock, struct sockaddr *sa,
		int sa_len, void *arg) {
	printf("Accepted connection, sockfd = %d\n", sock);
	struct event_base *evbase;
	struct bufferevent *bev;
	server_ctx_t *sctx = (server_ctx_t*) arg;
	SSL *ssl = SSL_new(sctx->ssl_ctx);


	evbase = evconnlistener_get_base(serv);
	
	bev = bufferevent_openssl_socket_new(evbase, sock, ssl,
			BUFFEREVENT_SSL_ACCEPTING,
			BEV_OPT_CLOSE_ON_FREE);

	bufferevent_enable(bev, EV_READ);
	//bufferevent_disable(bev, EV_WRITE); !! Do not disable EV_WRITE, or it will be not able to send data

	client_ctx_t *cctx = malloc(sizeof(client_ctx_t));
	memset(cctx, 0, sizeof(client_ctx_t));
	cctx->sctx = sctx;
	cctx->bev = bev;

	
	bufferevent_setcb(bev, sctx->read_cb, NULL, sctx->event_cb, cctx);
	
}
#if 0
void sslsvr_set_key_pair(char *keyfile, char* certfile) {
	assert(g_initialized);
	assert(keyfile);
	assert(certfile);


	if (! SSL_CTX_use_certificate_file(g_server_ssl_ctx, certfile, SSL_FILETYPE_PEM) ||
			! SSL_CTX_use_PrivateKey_file(g_server_ssl_ctx, keyfile, SSL_FILETYPE_PEM)) {
		ERR_print_errors_fp(stderr);
		exit(-1);
	}
}
/*
void sslsvr_set_cb(sslsvr_event_cb accept_cb, sslsvr_event_cb read_cb, sslsvr_event_cb eof_cb) {

	assert(g_initialized);
	assert(accept_cb);
	assert(read_cb);
	assert(eof_cb);
	g_accept_cb = accept_cb;
	g_read_cb = read_cb;
	g_eof_cb = eof_cb;
}
*/
void sslsvr_bind_port(short port) {
	assert(g_initialized);
	memset(&g_server_sin, 0, sizeof(g_server_sin));
	g_server_sin.sin_family = AF_INET;
	g_server_sin.sin_port = htons(port);
	g_server_sin.sin_addr.s_addr = 0; //htonl(0x7f000001); /* 127.0.0.1 */
}

void sslsvr_set_ctx(void *ctx) {
	assert(g_initialized);
	g_ctx = ctx;
}

void sslsvr_set_client_ctx(sslsvr_client_t *cli, void *ctx) {
	assert(cli);
	client_t *client = (client_t*)cli;
	client->ctx = ctx;
}

void *sslsvr_client_ctx_get(sslsvr_client_t *cli) {
	client_t *client = (client_t*)cli;
	return client->ctx;
}
void sslsvr_enable_verify(char *cafile, int depth) {
	assert(g_initialized);
	SSL_CTX_set_verify(g_server_ssl_ctx, SSL_VERIFY_PEER, NULL);
	if(SSL_CTX_load_verify_locations(g_server_ssl_ctx, cafile, NULL)  <= 0) {
		fprintf(stdout, "SSL_CTX_load_verify_locations:\n");
		ERR_print_errors_fp(stderr);
		exit(-1);
	}

}


void sslsvr_stop() {
	assert(g_initialized);
	assert(g_evbase);
	event_base_loopbreak(g_evbase);
}

const char *sslsvr_cipher_get(sslsvr_client_t *cli) {
	assert(cli);
	client_t * client = (client_t*) cli;
	/* Get connect use algorithm type */
	SSL *ssl = (SSL*) bufferevent_openssl_get_ssl(client->bev);
	if(ssl) return SSL_get_cipher(ssl);
	else return NULL;
}


int sslsvr_buf_len(sslsvr_client_t *cli) {
	assert(cli);
	client_t *client = (client_t*) cli;
	struct evbuffer *in = bufferevent_get_input(client->bev);
	return evbuffer_get_length(in);
}

int sslsvr_read(sslsvr_client_t *cli, unsigned char* buf, int len) {
	assert(cli);
	assert(len>=0);
	client_t *client = (client_t*) cli;
	if(buf) {
		return bufferevent_read(client->bev, buf, len);
	} else {
		//printf("client->bev = %p\n", client->bev);
		struct evbuffer * in = bufferevent_get_input(client->bev);
		return evbuffer_drain(in, len);
		
	}
}

int sslsvr_peek(sslsvr_client_t *cli, unsigned char* buf, int len) {
	assert(cli);
	assert(buf);
	client_t *client = (client_t*) cli;
	struct evbuffer *in = bufferevent_get_input(client->bev);
	return evbuffer_copyout(in, buf, len);
}
int sslsvr_write(sslsvr_client_t *cli, unsigned char* data, int len) {
	assert(cli);
	client_t *client = (client_t*) cli;
	return bufferevent_write(client->bev, data, len);
}
void sslsvr_close(sslsvr_client_t *cli) {
	client_t *client = (client_t*) cli;
	bufferevent_flush(client->bev, EV_WRITE, BEV_FLUSH);
	bufferevent_free(client->bev);
}

void sslsvr_destroy() {
	assert(g_initialized);
	SSL_CTX_free(g_server_ssl_ctx);
}

#endif


struct evconnlistener *server_init_listen(struct event_base *evbase, uint16_t port, server_ctx_t *sctx) {
	struct evconnlistener *listener;
	
	struct sockaddr_in bindaddr = {0};
	bindaddr.sin_family = AF_INET;
	bindaddr.sin_port = htons(port);
	bindaddr.sin_addr.s_addr = INADDR_ANY;

	listener = evconnlistener_new_bind(
			evbase, accept_cb, (void *)sctx,
			LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 1024,
			(struct sockaddr *)&bindaddr, sizeof(bindaddr));
	if(listener == NULL) {
		perror("evconnlistener_new_bind");
		exit(-1);
	}
	
	//assert(listener != NULL);
	
	return listener;
}
