#ifndef _SSLSVR_H_
#define _SSLSVR_H_
#include "ctx.h"
struct event_base;

SSL_CTX* server_ssl_ctx_init(
		const char *cafile,
		int depth,
		const char *keyfile,
		const char *certfile);

struct evconnlistener *server_init_listen(
		struct event_base *evbase,
		uint16_t port,
		server_ctx_t *sctx);
#endif
