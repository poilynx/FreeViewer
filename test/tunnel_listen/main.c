#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include <event2/event.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "tunnel.h"

#define LISTEN_PORT 8888
#define BIND_PORT 0

static SSL_CTX *make_listen_ctx(void)
{
	SSL_CTX  *ctx = SSL_CTX_new(SSLv23_server_method());
	//SSL_CTX  *ctx = SSL_CTX_new(TLS_server_method());
	
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);


	if (! SSL_CTX_use_certificate_file(ctx, "./certs/pubkey", SSL_FILETYPE_PEM) ||
			! SSL_CTX_use_PrivateKey_file(ctx, "./certs/prikey", SSL_FILETYPE_PEM)) {

		ERR_print_errors_fp(stderr);
		return NULL;
	}
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
			bufferevent_setcb(bev, NULL, write_cb, NULL, NULL);
			break;
		}
	}
	bufferevent_write_buffer(bev, in);
	evbuffer_drain(in, len);
}

void event_cb(struct bufferevent *bev, short events, void *arg) {
	if(events & BEV_EVENT_EOF);
	printf("event_cb events = %hx\n", events);
}

void listen_cb(tunnel_t *tun, const char *passwd, void *arg) {
	printf("listen_cb tun = %p, passwd = %s, arg = %p\n", tun, passwd, arg);
	if(strcmp(passwd, "abc") == 0) {
		tunnel_accept(tun);
		struct bufferevent *bev = tunnel_get_bufferevent(tun);
		bufferevent_enable(bev, EV_READ|EV_WRITE);
		bufferevent_setcb(bev, read_cb, NULL, event_cb, tun);
	} else {
		tunnel_reject(tun, TVS_PermissionDenied);
	}
}

int main() {
	struct event_base *base;
	base = event_base_new();
	assert(base);

	SSL_CTX *lctx = make_listen_ctx();
	assert(lctx);
	tunnel_listener_t * tlistener = tunnel_listener_new(base, LISTEN_PORT, lctx, listen_cb, NULL);
	event_base_loop(base, 0);
	tunnel_listener_free(tlistener);
	
	return 0;
}

