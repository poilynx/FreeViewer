#include "common.h"
#include "ctx.h"
#include "travproto.h"
#include "sslutil.h"
#include "client.h"
//void clientev_read_cb(struct bufferevent * bev, void * arg);
//void clientev_event_cb(struct bufferevent *bev, short events, void *arg);

static SSL_CTX *init_active_ssl(const char *cafile, X509 *cert, EVP_PKEY *key) {
	assert(cafile && cert && key);

	SSL_CTX  *ctx = SSL_CTX_new(SSLv23_client_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

	SSL_CTX_set_verify_depth(ctx, 0);

	if(SSL_CTX_load_verify_locations(ctx, cafile, NULL)  <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-1);
	}

	if(SSL_CTX_use_certificate(ctx, cert) == 0 || SSL_CTX_use_PrivateKey(ctx,key) == 0) {
		printf("cert or key file broken\n");
		ERR_print_errors_fp(stderr);
		exit(-1);
	}

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

	return ctx;
}




static int username_is_valid(trav_username_t *name) {
	char *p = (char*)name;
	for(int i=0; i<sizeof(trav_username_t); i++)
		if(p[i] == 0)
			return 1;
	return 0;
}

static size_t make_signin(uint8_t *buf) {
	printf("calling make_signin\n");
	uint8_t id = TRAV_MSG_SIGNIN;
	buf[0] = id;
	return 1;
}

static size_t make_register(uint8_t *buf, trav_username_t name) {
	buf[0] = TRAV_MSG_REGISTER;
	memcpy(buf + 1, name, sizeof(trav_username_t));
	return sizeof(trav_username_t) + 1;
}

#if 0
static size_t make_connect(uint8_t *buf) {
	return 0;
}

static size_t make_traverse_ready(uint8_t *buf) {
	return 0;
}

static size_t make_traverse_deny(uint8_t *buf) {
	return 0;
}
#endif


void clientev_read_cb(struct bufferevent * bev, void * arg) {
	printf("clientev_read_cb\n");
	uint8_t *readptr;
	size_t readlen = 0;
	uint8_t wbuf[2048]; size_t wbuflen = 0;
	struct evbuffer *in = bufferevent_get_input(bev);
	size_t inlen = evbuffer_get_length(in);
	uint8_t msgid = *evbuffer_pullup(in, 1);
	client_t *cli = (client_t*) arg;
	client_ctx_t *ctx  = cli->ctx;
	switch(msgid) {
		case TRAV_MSG_ERROR:
			printf("Received TRAV_MSG_ERROR\n");
			readlen = 2;
			if(inlen >= 2) {
				uint8_t err = evbuffer_pullup(in, 2)[1];
				printf("!! Received error %d\n", err);
				exit(-1);
			}
			break;
		case TRAV_MSG_SIGNIN_OK:
			printf("Received TRAV_MSG_SIGNIN_OK\n");
			printf("Sign in OK\n");
			readlen = 1;
			ctx->certified = 1;
			trav_username_t name;

			if(sslutil_ssl_get_local_CN(bufferevent_openssl_get_ssl(bev), name, sizeof(name))) {
				printf("read ssl CN error\n");
				exit(1);
			}

			

			cli->signin_cb(cli, TRAV_ERR_SUCCESS, name, cli->arg);
			break;
		case TRAV_MSG_SIGNIN_ERROR:
			printf("Received TRAV_MSG_SIGNIN_ERROR:\n");
			if(inlen >= 2) {
				uint8_t err = evbuffer_pullup(in,2)[1];
				printf("Sign in failed, err = %d\n", err);
				readlen = 2;
				cli->signin_cb(cli, err, NULL, cli->arg);
			}
			break;
		case TRAV_MSG_REGISTER_OK:
			printf("Received TRAV_MSG_REGISTER_OK:\n");
			if(inlen >= 1 + sizeof(trav_username_t)) {
				uint16_t len = ((trav_raw_data_t*)(evbuffer_pullup(in, 3) + 1))->length;
				printf("len = %hu\n", len);
				if(inlen >= 1 + sizeof(trav_raw_data_t) + len) {
					EVP_PKEY *key;
					X509 *cert;
					trav_raw_data_t * p, *rkey, *rcert;
					trav_username_t *name;
					p = (trav_raw_data_t*)(evbuffer_pullup(in, 1 + sizeof(trav_raw_data_t) + len) + 1);
 
					name = (trav_username_t*)(p->data);
					printf("username = %s\n", *name);
					rkey = (trav_raw_data_t*) (p->data + sizeof(trav_username_t));
					rcert = (trav_raw_data_t*) (rkey->data + rkey->length);
					printf("cert size = %hu, %hu\n", rkey->length, rcert->length);
					assert(p->length == sizeof(trav_username_t) + rkey->length + rcert->length + sizeof(trav_raw_data_t) *2);
					key = pem2key(rkey->data , rkey->length);
					cert = pem2cert(rcert->data , rcert->length);
					assert(key);
					assert(cert);

					if(save_key(key, cli->keyfile) || save_cert(cert, cli->certfile)) {
						printf("store key pair error\n");
					}

					ctx->cert = cert;
					ctx->key = key;
					ctx->certified = 1;
					printf("register ok, session begin.\n");
					memcpy(ctx->context.session.username,name, sizeof(trav_username_t));
					readlen = 1 + sizeof(trav_raw_data_t) + len;

					cli->signin_cb(cli, TRAV_ERR_SUCCESS, *name, cli->arg);
				}
			}
			break;
		case TRAV_MSG_REGISTER_ERROR:
			printf("Received TRAV_MSG_REGISTER_ERROR:\n");
			if(inlen >= 2) {
				uint8_t err = evbuffer_pullup(in,2)[1];
				printf("Register failed, err = %d\n", err);
				readlen = 2;
				cli->signin_cb(cli, err, NULL, cli->arg);
			}
			break;
		case TRAV_MSG_TRAVERSE:
			printf("Received TRAV_MSG_TRAVERSE\n");
			readlen = 1 + sizeof(trav_username_t) + sizeof(trav_address_t);
			if(inlen < readlen) {
				readlen = 0;
				break;
			}

			readptr = evbuffer_pullup(in, readlen);
			/* block */ {
				trav_username_t *active_name = (trav_username_t*)(readptr + 1);

				trav_address_t *active_addr;
				active_name = (trav_username_t*) (readptr + 1);
				active_addr = (trav_address_t*) (readptr + 1 + sizeof(trav_username_t));
				struct sockaddr_in sa;
				sa.sin_family = AF_INET;
				sa.sin_addr.s_addr = active_addr->ipaddr;
				sa.sin_port  = active_addr->port;
				printf("name = %s\n", *active_name);
				printf("addr = %s %hu\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port) );

				if(cli->listen_cb(cli, sa, *active_name, cli->ctx->context.session.connect.arg) == 0) {
					wbuf[wbuflen++] = TRAV_MSG_TRAVERSE_DENY;
				} else {
					wbuf[wbuflen++] = TRAV_MSG_TRAVERSE_READY;
				}
				memcpy(wbuf+wbuflen, active_name, sizeof(trav_username_t));
				wbuflen += sizeof(trav_username_t);
			}
			break;
		case TRAV_MSG_ACCEPT:
			printf("Received TRAV_MSG_ACCEPT:\n");
			readlen = 1 + sizeof(trav_username_t) + sizeof(trav_address_t);
			if(inlen < readlen) {
				readlen = 0;
				break;
			}
			readptr = evbuffer_pullup(in, readlen);
			/* block */ {
				struct sockaddr_in sa;

				trav_username_t *passive_name;
				trav_address_t *passive_addr;
				passive_name = (trav_username_t*) (readptr + 1);
				passive_addr = (trav_address_t*) (readptr + 1 + sizeof(trav_username_t));
				sa.sin_addr.s_addr = passive_addr->ipaddr;
				sa.sin_port = passive_addr->port;
				printf("name = %s\n", *passive_name);
				printf("addr = %s %hu\n", inet_ntoa(sa.sin_addr), ntohs(passive_addr->port) );

				if(username_is_valid(passive_name) == 0) {
					break;
				}
				if(ctx_connect_isvalid(ctx, 8) && strcmp(ctx->context.session.connect.peername, *passive_name) == 0) {
					cli->ctx->context.session.connect.connecting = 0;
					cli->ctx->context.session.connect.traverse_cb(cli, 0, &sa, cli->ctx->context.session.connect.arg);
				} else {
					cli->ctx->context.session.connect.connecting = 0;
					cli->ctx->context.session.connect.traverse_cb(cli, 255, NULL, cli->ctx->context.session.connect.arg);
				}
#if 0
				if(username_is_valid(passive_name) == 0) {
					break;
				}
				if(ctx_connect_isvalid(ctx, 8) && strcmp(ctx->context.session.connect.peername, *passive_name) == 0) {
						//ctx->context.session.connect.traverse_cb(NULL, 0, ctx->context.session.connect.arg);
						//TODO:
					struct bufferevent *tunbev;
						
					struct sockaddr_in sa;
					sa.sin_family = AF_INET;
					sa.sin_addr.s_addr = passive_addr->ipaddr;
					sa.sin_port = passive_addr->port;
					SSL *ssl = SSL_new(init_active_ssl(cli->cafile, cli->ctx->cert, cli->ctx->key));
					assert(ssl);
					tunbev = bufferevent_openssl_socket_new(
							bufferevent_get_base(bev),
							-1,
							ssl,
							BUFFEREVENT_SSL_CONNECTING,
							BEV_OPT_CLOSE_ON_FREE /*|  BEV_OPT_DEFER_CALLBACKS*/);
					if(tunbev == NULL) {
						printf("bufferevent_openssl_socket_new: %ld\n", bufferevent_get_openssl_error(tunbev));
						exit(-1);
					}

					bufferevent_setcb(tunbev, NULL, tunnel_write_cb, tunnel_event_cb, cli);
					bufferevent_enable(tunbev, EV_WRITE);
					bufferevent_settimeout(tunbev, 0, 4);//FIXME should fill left time

					assert(bufferevent_socket_connect(tunbev, (const struct sockaddr*)&sa, sizeof(sa)) == 0);
					
				}
#endif
			}
			break;
		case TRAV_MSG_REJECT:
			printf("Received TRAV_MSG_REJECT:\n");
			if(inlen >= 2) {
				uint8_t err = evbuffer_pullup(in,2)[1];
				printf("traverse failed, err = %d\n", err);
				readlen = 2;

				cli->ctx->context.session.connect.traverse_cb(cli, err, NULL, cli->ctx->context.session.connect.arg);
				cli->ctx->context.session.connect.connecting = 0;

			}
			break;
		default:
			printf("Received unknow msgid %d\n", msgid);
			exit(-1);
	}
	if(wbuflen) bufferevent_write(bev, wbuf, wbuflen);
	if(readlen) evbuffer_drain(in, readlen);
}

void clientev_event_cb(struct bufferevent *bev, short events, void *arg) {
	printf("clientev_event_cb event = %hX\n", events);
	client_t *cli = (client_t*) arg;
	client_ctx_t *ctx  = cli->ctx;
	uint8_t wbuf[2048]; size_t wbuflen = 0;

	struct event_base *evbase = bufferevent_get_base(bev);
	if(events & BEV_EVENT_EOF) {
		printf("eof\n");
	}
	
	if(events & BEV_EVENT_ERROR) {
		
		long ev_err = bufferevent_get_openssl_error(bev);
		if(errno) {
			printf("c error: %s\n", strerror(errno));
		} else if(ev_err) {
			printf("ssl error: %s\n", ERR_reason_error_string(ev_err));
		}
		event_base_loopbreak(evbase);
	}

	if(events & BEV_EVENT_EOF) {
		event_base_loopbreak(evbase);
	}
		
	if(events & BEV_EVENT_CONNECTED) {
		printf("Handshake OK\n");
		SSL * ssl;
		ssl = bufferevent_openssl_get_ssl(bev);
		X509 *cert = SSL_get_certificate(ssl);

		if(cert == NULL) {
			ctx->context.signin = signin_registering;
			trav_username_t name;
			strcpy(name, "lixilin");
			wbuflen = make_register(wbuf, name);
			printf("Send register\n");
		} else {
			wbuflen = make_signin(wbuf);
			printf("Send sign in\n");
		}
		
	}
	if(wbuflen) {
		printf("send %lu bytes\n", wbuflen);
		bufferevent_write(bev, wbuf, wbuflen);
	}
}

/*
void clientev_start_up(struct bufferevent *bev, void *arg) {

}
*/


