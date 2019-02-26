//#include "trav.h"
#include "common.h"
#include "client.h"

#define SERVER_ADDR	"127.0.0.1"
#define SERVER_PORT	6363
#define CLIENT_PORT 	6364
#define ACCESS_PORT	6400

void signin_cb(client_t *client, int ok, const char *name, void *arg) {
	printf("signin_cb\n");
}

/* return 1 on accept */
int listen_cb(client_t *client, struct sockaddr_in sa, const char *name, void *arg) {
	printf("listen_cb\n");
	return 1;
}

void traverse_cb(client_t *client, int errcode, struct sockaddr_in *sa, void *arg) {
	printf("traverse_cb\n");
}



int main(int argc, char **argv) {

	struct event_base *evbase;
		
	evbase = event_base_new();

	client_t *cli = trav_client_new(evbase, CA_FILE, KEY_FILE, CERT_FILE, signin_cb, listen_cb, NULL);
	if(trav_client_connect(cli, SERVER_ADDR, SERVER_PORT, 3006)) {
		perror("trav_client_connect");
		exit(1);
	}

	/* start event loop */
	int ret = event_base_loop(evbase, 0);
	

	printf("Event loop exit with %d\n", ret);
	event_base_free(evbase);

	return 0;
}
