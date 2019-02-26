#include "ctx.h"
#include "travproto.h"
#include <stdint.h>
struct bufferevent;
int cctx_init_session(
		client_ctx_t *cctx,
		struct bufferevent *bev,
		trav_username_t *name,
		server_ctx_t *sctx
) {
	cctx->certified = 1;
	cctx->bev = bev;
	memcpy(cctx->username, name, sizeof(trav_username_t));
	cctx->sctx = sctx;
	return 0;
}

