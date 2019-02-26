//#include "trav.h"
#include "common.h"
#include "client.h"

//#define SERVER_ADDR	"103.118.40.84"
#define SERVER_ADDR	"127.0.0.1"
#define SERVER_PORT	6363
#define CLIENT_PORT 	6366
#define ACCESS_PORT	6400


/*
   void show_certs_info(SSL* ssl)
   {
   X509 *cert;
   char *line;
   cert = SSL_get_peer_certificate(ssl);
   if ( cert != NULL )
   {
   printf("Server certificates:\n");
   line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
   printf("Subject: %s\n", line);
   free(line);
   line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
   printf("Issuer: %s\n", line);
   free(line);
   X509_free(cert);
   }
   else
   printf("No certificates.\n");
   }
*/

/* return 1 on accept */
int listen_cb(client_t *client, struct sockaddr_in sa, const char *name, void *arg) {
	printf("listen_cb\n");
	return 1;
}

void traverse_cb(client_t *client, int errcode, struct sockaddr_in *sa, void *arg) {
	printf("traverse_cb\n");
	if(errcode == 0) {
		printf("addr = %s, port = %hu\n", inet_ntoa(sa->sin_addr), ntohs(sa->sin_port));
	} else {
		printf("traverse failed %d\n", errcode);
	}
}

void signin_cb(client_t *client, int errcode, const char *name, void *arg) {
	printf("signin_cb\n");
	if(errcode == 0) {
		trav_client_traverse(client, "92", traverse_cb, NULL);
	} else {
		printf("sign in error %d\n", errcode);
		exit(-1);
	}
}

int main(int argc, char **argv) {

	struct event_base *evbase;
	evbase = event_base_new();

	client_t *cli = trav_client_new(evbase, CA_FILE, KEY_FILE, CERT_FILE, signin_cb, listen_cb, NULL);
	if(trav_client_connect(cli, SERVER_ADDR, SERVER_PORT, CLIENT_PORT)) {
		perror("trav_client_connect");
		exit(1);
	}


	/* start event loop */
	int ret = event_base_loop(evbase, 0);
	

	printf("Event loop exit with %d\n", ret);
	event_base_free(evbase);

	return 0;
}
