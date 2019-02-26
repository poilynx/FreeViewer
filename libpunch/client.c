#include <string.h>
#include "common.h"
#include "travproto.h"
#include "client.h"
#include "sslutil.h"
#include "tunnel.h"
#include "ctx.h"
#include "clientev.h"

/*
typedef void(*trav_client_signin_cb)(trav_client_t *client, int ok, const char *name);
typedef void(*trav_tunnel_listen_cb)(trav_tunnel_t *tun, const char *name, const char *passwd);
typedef void(*trav_tunnel_connect_cb)(trav_tunnel_t *tun, const char *name, int errcode, struct bufferevent *bev);
*/



static SSL_CTX *init_client_ssl(const char *cafile, X509 *cert, EVP_PKEY *key) {
	assert(cafile);

	SSL_CTX  *ctx = SSL_CTX_new(SSLv23_client_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

	SSL_CTX_set_verify_depth(ctx, 0);

	if(SSL_CTX_load_verify_locations(ctx, cafile, NULL)  <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-1);
	}

	if(cert && key) {
		if(SSL_CTX_use_certificate(ctx, cert) == 0 || SSL_CTX_use_PrivateKey(ctx,key) == 0) {
			printf("cert or key file broken\n");
			ERR_print_errors_fp(stderr);
			exit(-1);
		}
	}

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

	return ctx;
}


static struct bufferevent *connect_server(
		struct event_base *evbase,
		const char* remoteaddr, 
		unsigned short remoteport, 
		unsigned short bindport, 
		const char *ca,
		EVP_PKEY*key, X509 *cert
);
/*
static int verify_callback(int ok, X509_STORE_CTX *store)
{
        char data[256];
        if (ok)
        {
                X509 *cert = X509_STORE_CTX_get_current_cert(store);
                int  depth = X509_STORE_CTX_get_error_depth(store);
                int  err = X509_STORE_CTX_get_error(store);

                printf("Certificate at depth: %i\n", depth);
                memset(data, 0, sizeof(data));
                X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
                printf("\tIssuer = %s\n", data);
                X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
                printf("\tSubject = %s\n", data);
                printf("\terror status: %i:%s\n", err, X509_verify_cert_error_string(err));

		printf("\tSerial number: ");
		ASN1_INTEGER *aint = X509_get_serialNumber(cert);

		for(int i=0;i<aint->length;i++) {
			printf("%hhX:", aint->data[i]);
		}
		putchar('\n');
        }
        return ok; 
}
*/
static struct bufferevent *connect_server(
		struct event_base *evbase,
		const char* remoteaddr, 
		unsigned short remoteport, 
		unsigned short bindport, 
		const char*cafile,
		EVP_PKEY*key, X509 *cert
) {
	struct bufferevent *bevclient;
	struct sockaddr_in bindaddr;
	struct sockaddr_in serveraddr;
	SSL * client_ssl;
	int client_sock;

	memset(&bindaddr, 0, sizeof(bindaddr));
	bindaddr.sin_family = AF_INET;
	bindaddr.sin_port = htons(bindport);
	bindaddr.sin_addr.s_addr = INADDR_ANY;

	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(remoteport);
	serveraddr.sin_addr.s_addr = inet_addr(remoteaddr);

	/* create a binding socket for connection */
	client_sock = socket(AF_INET, SOCK_STREAM, 0);
	evutil_make_listen_socket_reuseable_port(client_sock);
	evutil_make_listen_socket_reuseable(client_sock);
	if(bind(client_sock, (const struct sockaddr*)&bindaddr, sizeof(bindaddr)) != 0) {
		perror("bind");
		exit(-1);
	}
	

	/* connect to remote*/
	if(connect(client_sock,(const struct sockaddr*)&serveraddr, sizeof(serveraddr)) != 0) {
		return NULL;
	}

	client_ssl = SSL_new(init_client_ssl(cafile, cert, key));
	/* FIXME: init_client_ssl returned value not free */

	bevclient = bufferevent_openssl_socket_new(
			evbase,
			client_sock,
			client_ssl,
			BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE /*|  BEV_OPT_DEFER_CALLBACKS*/);
	if(bevclient == NULL) {
		printf("bufferevent_openssl_socket_new: %ld\n", bufferevent_get_openssl_error(bevclient));
		exit(-1);
	}
	//bufferevent_socket_connect_hostname(bevclient, NULL, 0, "127.0.0.1", 6363);
	
	//bufferevent_enable(bevclient, EV_READ/*|EV_CLOSED*/);
	//bufferevent_setcb(bevclient, read_cb, write_cb, event_cb, NULL);
	return bevclient;

}



client_t* trav_client_new(
		struct event_base *evbase,
		const char *cafile,
		const char *keyfile,
		const char *certfile,
		client_signin_cb signin_cb,
		client_listen_cb listen_cb,
		void *arg
) {
	client_t *cli = malloc(sizeof(client_t));
	

	cli->evbase = evbase;

	cli->ctx = malloc(sizeof(client_ctx_t));
	if(cli->ctx == NULL) {
		perror("malloc");
		exit(-1);
	}
	memset(cli->ctx, 0, sizeof(client_ctx_t));

	cli->keyfile = strdup(keyfile);
	cli->certfile = strdup(certfile);
	cli->cafile = strdup(cafile);
	if(cli->keyfile == NULL || cli->certfile == NULL || cli->cafile == NULL) {
		perror("strdup");
		exit(-1);
	}

	cli->listen_cb = listen_cb;

	cli->bev = NULL;

	(void)load_key_pair(keyfile, &cli->ctx->key, certfile, &cli->ctx->cert);

	cli->signin_cb = signin_cb;

	cli->arg = arg;
	return cli;

#if 0	
		
#endif

}

int trav_client_connect(
		client_t *client,
		const char* remoteaddr,
		unsigned short port,
		unsigned short bindport
) {
	client_t *cli = (client_t*)client;
	struct bufferevent *bev;
	/* init client */
	if((bev = connect_server(cli->evbase, remoteaddr, port, bindport, cli->cafile, cli->ctx->key, cli->ctx->cert)) == NULL) {
		perror("connect_server");
		return -1;
	}
	cli->bev = bev;

	/* set read and event callback */
	bufferevent_enable(bev, EV_READ);
	bufferevent_setcb(bev, clientev_read_cb, NULL, clientev_event_cb, cli);

	//cli->tlistener = tunnel_listener_new(bufferevent_get_base(bev), bindport, cli->listen_cb, NULL);
	//assert(cli->tlistener);

	return 0;
}

void trav_client_free(client_t *client) {
	free((void*)client->cafile);
	free((void*)client->keyfile);
	free((void*)client->certfile);
	if(client->ctx->cert)
		X509_free(client->ctx->cert);
	if(client->ctx->key)
		EVP_PKEY_free(client->ctx->key);
	free(client->ctx);
	free(client);


}

/* return 0 if success, -1 if send error */
int trav_client_traverse(
		client_t *client,
		const char *peername,
		client_traverse_cb traverse_cb,
		void* arg
) {
	client_ctx_t * ctx = client->ctx;
	int wbuflen = 1 + sizeof(trav_username_t), namelen;
	char wbuf[wbuflen];

	assert(client && peername && traverse_cb);
	if(client->ctx->certified == 0)
		return -1;

	namelen = strlen(peername);

	if(namelen == 0 || namelen >= sizeof(trav_username_t)) {
		printf("peername incorrect.\n");
		exit(1);
	}
	if(ctx_connect_isvalid(ctx, 8)) {
		printf("traverse busy\n");
		return 1;
	}
	
	ctx->context.session.connect.traverse_cb = traverse_cb;
	ctx->context.session.connect.connecting = 1;
	strcpy(ctx->context.session.connect.peername, peername);
	time(&ctx->context.session.connect.conntime);
	ctx->context.session.connect.arg = arg;

	wbuf[0] = TRAV_MSG_CONNECT;
	strcpy(wbuf + 1, peername);
	return bufferevent_write(client->bev, wbuf, wbuflen);
}

unsigned short trav_client_local_port(client_t *client) {
	int fd = bufferevent_getfd(client->bev);
	if(fd < 0)
		return -1;
	struct sockaddr_in sa;
	unsigned int len = sizeof(sa);
	if(getsockname(fd, (struct sockaddr*)&sa, &len))
		return -1;
	return sa.sin_port;
}
