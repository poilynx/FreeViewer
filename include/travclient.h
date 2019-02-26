#ifndef _CLIENT_H_
#define _CLIENT_H_

#ifdef __cplusplus
extern "C" {
#endif

struct bufferevent;
struct event_base;
struct client_ctx_st;
struct client_st;
struct sockaddr_in;

typedef struct client_st client_t;
typedef struct client_ctx_st client_ctx_t;

typedef void(*client_signin_cb)(client_t *client, int errcode, const char *name, void *arg);

/* return 1 on accept */
typedef int(*client_listen_cb)(client_t *client, struct sockaddr_in sa, const char *name, void *arg);

typedef void(*client_traverse_cb)(client_t *client, int errcode, struct sockaddr_in *sa, void *arg);

struct client_st {
	struct event_base *evbase;
	client_ctx_t *ctx;
	struct bufferevent *bev;
	const char *keyfile;
	const char *certfile;
	const char *cafile;
	client_signin_cb signin_cb;
	client_listen_cb listen_cb;
	void *arg;
};

client_t* trav_client_new(
		struct event_base *evbase,
		const char *cafile,
		const char *keyfile,
		const char *certfile,
		client_signin_cb signin_cb,
		client_listen_cb listen_cb,
		void *arg
);

int trav_client_connect(
		client_t *client,
		const char* remoteaddr,
		unsigned short port,
		unsigned short bindport
);

void trav_client_free(client_t *client);

int trav_client_traverse(
		client_t *client,
		const char *peername,
		client_traverse_cb traverse_cb,
		void* arg
);

unsigned short trav_client_local_port(client_t *client);

#ifdef __cplusplus
}
#endif

#endif
