#ifndef _TUNNEL_H_
#define _TUNNEL_H_
#include <stdint.h>

#define MAX_NAME_LENGTH 32
#define MAX_PASSWD_LENGTH 40

struct event_base;
struct bufferevent;
struct evconnlistener;
struct sockaddr_in;
struct ssl_ctx_st;

struct tunnel_st;
struct tunnel_ctx_st;


typedef struct tunnel_ctx_st tunnel_ctx_t;
typedef struct tunnel_listener_st tunnel_listener_t;

enum tunnel_verify_status_en {
	TVS_OK,
	TVS_Busy,
	TVS_PermissionDenied,
	TVS_Forbidden,
	TVS_Unknow = 9
};

enum connect_err_en {
	CONNECT_ERR_SUCCESS,
	CONNECT_ERR_TIMEOUT,
	CONNECT_ERR_UNREACHED,
	CONNECT_ERR_SSL,
	CONNECT_ERR_UNKNOW
};

typedef struct tunnel_st tunnel_t;
typedef void(*tunnel_connect_cb)(tunnel_t *tun, enum connect_err_en errcode, void *arg);
typedef void(*tunnel_verify_cb)(tunnel_t *tun, int status, void *arg);
typedef void(*tunnel_listen_cb)(tunnel_t *tun, const char *passwd, void *arg);

tunnel_listener_t *tunnel_listener_new(struct event_base *evbase, uint16_t port,
		struct ssl_ctx_st *sslctx, tunnel_listen_cb listen_cb, void *arg);

void tunnel_listener_punch(tunnel_listener_t *tlistener, const struct sockaddr_in *sa);
void tunnel_listener_free(tunnel_listener_t *tlistener);

void tunnel_accept(tunnel_t *tun);
void tunnel_reject(tunnel_t *tun, uint8_t status_code);

const char *tunnel_get_listener_name(tunnel_t *tun);

tunnel_t *tunnel_connect(struct event_base *evbase, const struct sockaddr_in *addr, uint16_t bindport, const char *name,
		const struct ssl_ctx_st *sslctx, tunnel_connect_cb connect_cb, tunnel_verify_cb verify_cb, void *arg);

int tunnel_verify(tunnel_t *tun, const char *passwd);

struct bufferevent *tunnel_get_bufferevent(tunnel_t *tun);

#endif
