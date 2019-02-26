#include "ctx.h"
#include "client.h"
#include <time.h>
#include <string.h>
int ctx_connect_isvalid(client_ctx_t *ctx, unsigned int timeout) {
	if(ctx->context.session.connect.connecting == 1) {
		time_t now;
		double interval;
		time(&now);
		interval = difftime(now, ctx->context.session.connect.conntime);
		if(interval >= 0 && interval <= timeout)
			return 1;
	}
	return 0;
}

void ctx_start_connect(client_ctx_t *ctx, trav_username_t *name, client_traverse_cb traverse_cb) {
	ctx->context.session.connect.connecting = 1;
	time(&ctx->context.session.connect.conntime);
	memcpy(&ctx->context.session.connect.peername , name, sizeof(trav_username_t));
}
