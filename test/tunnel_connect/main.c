#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "tunnel.h"

#define REMOTE_PORT 8888
#define BIND_PORT 0


static SSL_CTX *make_connect_ctx(void)
{
	SSL_CTX  *ctx = SSL_CTX_new(SSLv23_client_method());
	
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

	if(! SSL_CTX_load_verify_locations(ctx, "../../certs/root.cert", NULL)) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}
	/*
	if (! SSL_CTX_use_certificate_file(ctx, "./certs/pubkey", SSL_FILETYPE_PEM) ||
			! SSL_CTX_use_PrivateKey_file(ctx, "./certs/prikey", SSL_FILETYPE_PEM)) {

		ERR_print_errors_fp(stderr);
		return NULL;
	}
	*/
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

	return ctx;
}

void write_cb(struct bufferevent *bev, void *arg) {
	if(evbuffer_get_length(bufferevent_get_output(bev)) == 0)
		bufferevent_free(bev);
}

void read_cb(struct bufferevent *bev, void *arg) {
	struct evbuffer *in = bufferevent_get_input(bev);
	int i, len = evbuffer_get_length(in);
	unsigned char *p = evbuffer_pullup(in, -1);
	for(i=0; i<len; i++) {
		putchar(*(p+i));
		if(*(p+i) == '\n') {
			//bufferevent_setcb(bev, NULL, write_cb, NULL, NULL);
			break;
		}
	}
	evbuffer_drain(in, len);
}

void event_cb(struct bufferevent *bev, short events, void *arg) {
	//printf("event_cb events = %hx\n", events);
	if(events & BEV_EVENT_EOF) {
		bufferevent_free(bev);
	}
}



void connect_cb(tunnel_t *tun, enum connect_err_en errcode, void *arg) {
	//printf("connect_cb tun = %p, errcode = %d, arg = %p\n", tun, errcode, arg);
	if(errcode == CONNECT_ERR_SUCCESS) {
		tunnel_verify(tun, "abc");
	} else {
		printf("errcode = %d\n", errcode);
	}
}

void verify_cb(tunnel_t *tun, int status, void *arg) {
	//printf("verify_cb\n");
	//printf("status = %d\n", status);
	if(status == 0) {
		struct bufferevent *bev;
		bev = tunnel_get_bufferevent(tun);
		bufferevent_enable(bev, EV_WRITE|EV_READ);
		bufferevent_setcb(bev, read_cb, NULL, event_cb, tun);
		bufferevent_write(bev, "helloworld\n", sizeof("helloworld\n"));
	} else {
		printf("remote deny\n");
	}
}

void listen_cb(struct bufferevent *bev, const char *name, const char *passwd, void *arg) {
	//printf("listen_cb name = %s, passwd = %s, arg = %p\n", name, passwd, arg);
}

int main() {
	struct event_base *base;
	base = event_base_new();
	assert(base);

	/*
	SSL_CTX *lctx = make_listen_ctx();
	assert(lctx);
	tunnel_listener_t * tlistener = tunnel_listener_new(base, LISTEN_PORT, lctx, listen_cb, NULL);
	*/
	SSL_CTX *cctx = make_connect_ctx();
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(0x7F000001);
	//sa.sin_addr.s_addr = inet_addr("1.190.126.68");
	sa.sin_port = htons(REMOTE_PORT);
	tunnel_t *tun = tunnel_connect(base, &sa, BIND_PORT, "3", cctx, connect_cb, verify_cb, NULL);
	event_base_loop(base, 0);
	(void)(tun);
	return 0;
}

