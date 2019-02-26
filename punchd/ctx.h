#ifndef _CTX_H_
#define _CTX_H_
#include "travproto.h"
#include "avltree.h"
#include "issue.h"
#include <event2/bufferevent.h>
#include <string.h>
#include <stdint.h>
#include <openssl/ssl.h>

typedef struct {
	issue_template_t *issue_tpl;
	tree_t *sess_tab;
	SSL_CTX *ssl_ctx;
	bufferevent_event_cb event_cb;
	bufferevent_data_cb read_cb;
	bufferevent_data_cb write_cb;
} server_ctx_t;

typedef struct {

	int certified; //set 1 if peer support cert

	//int signedin; //set 1 if allow sign in
	trav_username_t username;
	struct bufferevent *bev; //set when bind cctx
	trav_address_t address;

	int connecting;
	trav_username_t peername;
	time_t conntime;

	uint8_t error;
	server_ctx_t *sctx;
} client_ctx_t;

int cctx_init_session(
		client_ctx_t *cctx,
		struct bufferevent *bev,
		trav_username_t *name,
		server_ctx_t *sctx
);
#endif
