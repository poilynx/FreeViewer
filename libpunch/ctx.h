#ifndef _CTX_H_
#define _CTX_H_
#include "travproto.h"
#include "client.h"
#include "tunnel.h"
#include <openssl/ssl.h>
#include <time.h>

typedef struct client_ctx_st{
	EVP_PKEY *key;
	X509 *cert;
	int certified;
	union {
		enum {
			signin_none,
			signin_registering,
			signin_signingin
		} signin;
		struct {
			trav_username_t username;
			/*
			struct {
				trav_username_t *allowtable;
				int allowtable_len;
			} accept;
			*/
			struct {
				int connecting;
				trav_username_t peername;
				client_traverse_cb traverse_cb;
				time_t conntime;
				void *arg;
			} connect;
		} session;
	} context;
} client_ctx_t;

int ctx_connect_isvalid(client_ctx_t *ctx, unsigned int timeout);
void ctx_start_connect(client_ctx_t *ctx, trav_username_t *name, client_traverse_cb traverse_cb);

#endif
