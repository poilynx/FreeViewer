/* C standard header */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* socket header */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

/* openssl header */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

/* libevent header */
#include <event.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>
#include <event2/dns.h>

#define CERT_FILE	"./certs/pubkey"
#define KEY_FILE	"./certs/prikey"
#define CA_FILE		"../../certs/root.cert"

