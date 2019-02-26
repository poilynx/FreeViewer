#include <stdio.h>
#include <assert.h>
#include <event.h>

#include <event2/listener.h>

#include "usermgr.h"
#include "issue.h"
#include "server.h"
#include "ctx.h"
#include "serverev.h"
#include "avltree.h"
int main() {
	struct evconnlistener *listener;
	struct event_base *evbase = event_base_new();

	usermgr_init();
	issue_init();
	
	
	assert(evbase);

	server_ctx_t * sctx = malloc(sizeof(server_ctx_t));

	sctx->issue_tpl = issue_template_new("../certs/root.key", "../certs/root.cert", "CN", "Jmpesp", 2048);
	assert(sctx->issue_tpl);

	sctx->ssl_ctx  = server_ssl_ctx_init("../certs/root.cert", 0, "../certs/server.key", "../certs/server.cert");;
	assert(sctx->ssl_ctx);

	sctx->sess_tab = tree_new();
	assert(sctx->sess_tab);

	sctx->read_cb = serverev_read_cb;
	sctx->write_cb = serverev_write_cb;
	sctx->event_cb = serverev_event_cb;
	

	listener = server_init_listen(evbase, 6363, sctx);
	assert(listener);
	printf("Listen on 6363\n");

	int ret = event_base_loop(evbase, 0);
	printf("Event loop exit with %d.\n", ret);

	evconnlistener_free(listener);

	return 0;
}
