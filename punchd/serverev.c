#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>


#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>

#include "ctx.h"
#include "usermgr.h"
#include "travproto.h"
#include "issue.h"
#include "avltree.h"
#include "sslutil.h"
static int bev_get_peer_addr(struct bufferevent *bev, uint32_t *ipaddr_ptr, uint16_t *port_ptr) {
	int sockfd = bufferevent_getfd(bev);
	struct sockaddr_in peersin;
	socklen_t len = sizeof(peersin);
	if(getpeername(sockfd, (struct sockaddr *)&peersin, &len)) {
		perror("getpeername");
		return -1;
	}
	*ipaddr_ptr = peersin.sin_addr.s_addr;
	*port_ptr = peersin.sin_port;
	return 0;
}

static int username_is_valid(trav_username_t *name) {
	char *p = (char*)name;
	for(int i=0; i<sizeof(trav_username_t); i++)
		if(p[i] == 0)
			return 1;
	return 0;
}

static void remove_client(client_ctx_t *cctx, server_ctx_t *sctx) {
	if(cctx->certified) {
		printf("Remove session of `%s'\n", cctx->username);
		tree_remove(sctx->sess_tab, cctx->username);
	}

	printf("Remove context of `%s'\n", cctx->username);
	free(cctx);
	printf("Close sock fd %d\n", bufferevent_getfd(cctx->bev));
	bufferevent_free(cctx->bev);
}

void serverev_event_cb(struct bufferevent *bev, short events, void *arg) {
	printf("serverev_event_cb %hu\n", events);
	client_ctx_t *cctx = (client_ctx_t*) arg;
	server_ctx_t *sctx = (server_ctx_t*) cctx->sctx;
	if(events & (BEV_EVENT_ERROR|BEV_EVENT_EOF)) {
		if(events & BEV_EVENT_EOF) {
		}
		remove_client(cctx, sctx);
	} else if(events & BEV_EVENT_CONNECTED) {
		printf("Handshake OK\n");
		if(bufferevent_openssl_get_ssl(bev)) {
			/* no thing */
		}
		
	}
}

void serverev_read_cb(struct bufferevent *bev, void *arg) {
	printf("There are data to read\n");
	int closing = 0;
	uint8_t *readptr; size_t readlen = 0;
	uint8_t wbuf[2048]; size_t wbuflen = 0;

	struct evbuffer *in = bufferevent_get_input(bev);
	size_t inlen = evbuffer_get_length(in);
	uint8_t msgid = *evbuffer_pullup(in, 1);
	client_ctx_t *cctx = (client_ctx_t*) arg;
	server_ctx_t *sctx = (server_ctx_t*) cctx->sctx; 

	switch(msgid) {
		case TRAV_MSG_SIGNIN: 
			readlen = 1;
			printf("TRAV_MSG_SIGNIN:\n");
			if(cctx->certified == 0) {
				char namebuf[sizeof(trav_username_t)] = {0};
				SSL *ssl = bufferevent_openssl_get_ssl(bev);
				if(ssl) {
					X509 *cert = SSL_get_peer_certificate(ssl);
					assert(cert);
					char *serial_number = sslutil_cert_get_serial_number(cert);
					assert(serial_number);
					assert(strlen(serial_number) <= 40);

					printf("Peer cert serial number: %s\n", serial_number);

					if(sslutil_ssl_get_peer_CN(ssl, namebuf, sizeof(namebuf)) == 0) {
						if(username_is_valid(&namebuf) == 1) {
							if(usermgr_check_passwd(namebuf, serial_number) == 0) {
								//printf("sess = %p\n", sctx->sess_tab);
								client_ctx_t **ctx;
								if((ctx = (client_ctx_t**)tree_find(sctx->sess_tab, namebuf)) != NULL) {
									printf("**ctx = %p\n", ctx);
									printf("already sign in, replace.\n");
									remove_client(*ctx, sctx);
																	
									//TODO
									/*
									printf("send TRAV_MSG_SIGNIN_ERROR: already in session\n");
									wbuf[wbuflen++] = TRAV_MSG_SIGNIN_ERROR;
									wbuf[wbuflen++] = TRAV_ERR_UNKNOW;//user is already in session table
									closing = 1;
									*/
								}

								printf("send TRAV_MSG_SIGNIN_OK\n");
								//cctx->signedin = 1; // ok
								//cctx->certified = 1; // ok
								wbuf[wbuflen++] = TRAV_MSG_SIGNIN_OK;
								tree_set(sctx->sess_tab, namebuf, cctx);
								//strcpy(cctx->username, namebuf);
								cctx_init_session(cctx, bev, &namebuf, sctx);

								usermgr_renew(namebuf);



							} else {
								printf("send TRAV_MSG_SIGNIN_ERROR: serial number error\n");
								wbuf[wbuflen++] = TRAV_MSG_SIGNIN_ERROR;
								wbuf[wbuflen++] = TRAV_ERR_UNKNOW;//serial number error
								closing = 1;
							}
						} else {
							printf("send TRAV_MSG_SIGNIN_ERROR: invalid username\n");
							wbuf[wbuflen++] = TRAV_MSG_SIGNIN_ERROR;
							wbuf[wbuflen++] = TRAV_ERR_UNKNOW;//invalid username
							closing = 1;
						}
					} else {
						printf("send TRAV_MSG_SIGNIN_ERROR: username too long\n");
						wbuf[wbuflen++] = TRAV_MSG_SIGNIN_ERROR;
						wbuf[wbuflen++] = TRAV_ERR_UNKNOW;//too long
						closing = 1;
					}
				} else {
					printf("send TRAV_MSG_SIGNIN_ERROR: no cert\n");
					wbuf[wbuflen++] = TRAV_MSG_SIGNIN_ERROR;
					wbuf[wbuflen++] = TRAV_ERR_UNKNOW;//no cert
					closing = 1;
				}
			} else {
				printf("send TRAV_MSG_SIGNIN_ERROR: already signed\n");
				wbuf[wbuflen++] = TRAV_MSG_SIGNIN_ERROR;
				wbuf[wbuflen++] = TRAV_ERR_UNKNOW;// already signed
				closing = 1;
			}
			break;
		case TRAV_MSG_REGISTER:
			readlen = 1 + sizeof(trav_username_t);
			printf("Received TRAV_MSG_REGISTER:\n");
			
			if(inlen >= sizeof(trav_username_t) + 1) {
				
				if(cctx->certified == 0) {
					//char namebuf[sizeof(trav_username_t)] = {0};
					trav_username_t *pname;
					trav_username_t realname;
					readptr = evbuffer_pullup(in, sizeof(trav_username_t));
					pname = (trav_username_t*)(readptr + 1);
					if(username_is_valid(pname) == 0) {
						printf("name is valid\n");
						wbuf[wbuflen++] = TRAV_MSG_REGISTER_ERROR;
						wbuf[wbuflen++] = TRAV_ERR_UNKNOW; //username invalid
						closing = 1;
						break;
					}

					if(usermgr_add_user(*pname, "", realname) == 0) {
						X509 *cert;
						EVP_PKEY *key;
						printf("Add user `%s' OK\n", realname);
						if(issue_sign(cctx->sctx->issue_tpl, realname, &key, &cert) == 0) {
							printf("Sign certificate OK\n");
							uint8_t *key_bytes = NULL;
							uint8_t *crt_bytes = NULL;
							size_t key_size = issue_key_to_pem(key, &key_bytes);
							size_t crt_size = issue_crt_to_pem(cert, &crt_bytes);
							trav_raw_data_t *raw;
							//trav_username_t *pname;

							char *serial_number = sslutil_cert_get_serial_number(cert);
							assert(usermgr_change_passwd(realname, serial_number) == 0);
							free(serial_number);
							
							wbuf[wbuflen++] = TRAV_MSG_REGISTER_OK;
							raw = (trav_raw_data_t*)&wbuf[wbuflen];
							raw->length = sizeof(trav_username_t)
								+ sizeof(trav_raw_data_t) * 2 
								+ key_size + crt_size;

							wbuflen += sizeof(trav_raw_data_t);
							memcpy(raw->data, realname, sizeof(trav_username_t));
							wbuflen += sizeof(trav_username_t);

							bufferevent_write(bev, wbuf, wbuflen);
							printf("Send id + size + username\n");

							raw = (trav_raw_data_t*)wbuf;
							raw->length = key_size;
							bufferevent_write(bev, wbuf, sizeof(trav_raw_data_t));
							printf("Send key size\n");

							bufferevent_write(bev, key_bytes, key_size);
							printf("Send key body\n");

							raw = (trav_raw_data_t*)wbuf;
							raw->length = crt_size;
							bufferevent_write(bev, wbuf, sizeof(trav_raw_data_t));
							printf("Send cert size\n");

							bufferevent_write(bev, crt_bytes, crt_size);
							printf("Send cert body\n");

							tree_set(sctx->sess_tab, realname, cctx);
							

							cctx_init_session(cctx, bev, &realname, sctx);
							
							//memcpy(cctx->username, realname, sizeof(trav_username_t));

							free(key_bytes);
							free(crt_bytes);

							wbuflen = 0;

						} else {
							printf("adduser error\n");
							usermgr_delete_user(realname);
							wbuf[wbuflen++] = TRAV_MSG_REGISTER_ERROR; //adduser error
							wbuf[wbuflen++] = TRAV_ERR_UNKNOW;
						}

					} else {
						printf("sign error\n");
						wbuf[wbuflen++] = TRAV_MSG_REGISTER_ERROR; //issue error
						wbuf[wbuflen++] = TRAV_ERR_UNKNOW;
					}
				} else {
					printf("certified = 1\n");
					wbuf[wbuflen++] = TRAV_MSG_REGISTER_ERROR; //already signed
					wbuf[wbuflen++] = TRAV_ERR_UNKNOW;
				}
			}
			break;
		case TRAV_MSG_CONNECT:
			readlen = 1 + sizeof(trav_username_t);
			if(inlen < readlen) {
				readlen = 0;
				break;
			}

			readptr = evbuffer_pullup(in, readlen);

			if(cctx->certified == 0) {
				wbuf[wbuflen++] = TRAV_MSG_ERROR;
				wbuf[wbuflen++] = TRAV_ERR_UNKNOW;
				closing = 1;
				break;
			}

			/* block */ {
				trav_username_t peername = {0};
				memcpy(peername, readptr+1, sizeof(trav_username_t));
				if(username_is_valid(&peername) == 0) {
					wbuf[wbuflen++] = TRAV_MSG_REJECT;
					wbuf[wbuflen++] = TRAV_ERR_UNKNOW; //username is not valid
					break;
				}

				if(cctx->connecting == 1) {
					time_t now;
					double interval;
					time(&now);
					interval = difftime(cctx->conntime, now);
					if(interval > 0 && interval < 8) {
						wbuf[wbuflen++] = TRAV_MSG_REJECT;
						wbuf[wbuflen++] = TRAV_ERR_UNKNOW; //there is a valid connection request in processing
						break;
					}
				}

				client_ctx_t **peerctx;
				if((peerctx = (client_ctx_t**)tree_find(sctx->sess_tab, peername)) == NULL) {
					wbuf[wbuflen++] = TRAV_MSG_REJECT;
					wbuf[wbuflen++] = TRAV_ERR_UNKNOW; //user to connect is not in session table
					break;
				}

				int peerbuflen = 0;
				char peerbuf[1 + sizeof(trav_username_t) + sizeof(trav_address_t)];
				trav_address_t * paddr;

				peerbuf[peerbuflen++] = TRAV_MSG_TRAVERSE;

				memcpy(peerbuf + peerbuflen, cctx->username, sizeof(trav_username_t));
				peerbuflen += sizeof(trav_username_t);

				paddr = (trav_address_t *)(peerbuf + peerbuflen);
				//paddr->ipaddr = htonl(
				assert(bev_get_peer_addr(bev, &paddr->ipaddr, &paddr->port) == 0);
				peerbuflen += sizeof(trav_address_t);
				
				cctx->connecting = 1;
				memcpy(cctx->peername, peername, sizeof(trav_username_t));
				time(&cctx->conntime);

				bufferevent_write((*peerctx)->bev, peerbuf, peerbuflen);
				printf("send traverse msg\n");
			}



			break;
		case TRAV_MSG_TRAVERSE_READY:
			readlen = 1 + sizeof(trav_username_t);
			if(inlen < readlen) {
				readlen = 0;
				break;
			}

			readptr = evbuffer_pullup(in, readlen);

			if(cctx->certified == 0) {
				wbuf[wbuflen++] = TRAV_MSG_ERROR;
				wbuf[wbuflen++] = TRAV_ERR_UNKNOW; //incorrect
				closing = 1;
				break;
			}


			/* block */ {
				printf("Received TRAV_MSG_TRAVERSE_READY:\n");
				trav_username_t activename = {0};
				memcpy(activename, readptr+1, sizeof(trav_username_t));
				if(username_is_valid(&activename) == 0) {
					break;
				}

				client_ctx_t **peerctx;
				if((peerctx = (client_ctx_t**)tree_find(sctx->sess_tab, activename)) == NULL) {
					break;
				}

				if((*peerctx)->connecting != 1)
					break;

				time_t now;
				time(&now);

				if(strcmp((*peerctx)->peername, cctx->username) != 0) { //didn't send traverse request
					printf("%s %s\n", (*peerctx)->peername, cctx->username);
					printf("username incompatible\n");
					break;
				}

				if(difftime(now, (*peerctx)->conntime) > 6) { //timeout
					(*peerctx)->connecting = 0;
					printf("timeout\n");
					break;
				}
				
				int peerbuflen = 0;
				char peerbuf[1 + sizeof(trav_username_t) + sizeof(trav_address_t)];

				peerbuf[peerbuflen++] = TRAV_MSG_ACCEPT;

				memcpy(peerbuf + peerbuflen, cctx->username, sizeof(trav_username_t));
				peerbuflen += sizeof(trav_username_t);

				trav_address_t *paddr = (trav_address_t*)(peerbuf + peerbuflen);
				bev_get_peer_addr(bev, &paddr->ipaddr, &paddr->port);
				peerbuflen += sizeof(trav_address_t);

				bufferevent_write((*peerctx)->bev, peerbuf, peerbuflen);
			}



			break;
		case TRAV_MSG_TRAVERSE_DENY:
			break;
		default:
			printf("Received unknow msgid %d\n", msgid);
			exit(-1);
	}

	printf("Total W R C %lu %lu %d\n", wbuflen, readlen, closing);
	if(wbuflen) bufferevent_write(bev, wbuf, wbuflen);
	if(readlen) evbuffer_drain(in, readlen);
	//bufferevent_flush(bev, EV_WRITE, BEV_FLUSH|BEV_FINISHED);
	if(closing) {
		bufferevent_setcb(bev, NULL, sctx->write_cb, NULL, arg);
		printf("closing ...\n");
	}
}

void serverev_write_cb(struct bufferevent *bev, void *arg) {
	client_ctx_t *cctx = (client_ctx_t*) arg;
	server_ctx_t *sctx = (server_ctx_t*) cctx->sctx; 
	struct evbuffer *out = bufferevent_get_output(bev);
	if(evbuffer_get_length(out) == 0) {
		remove_client(cctx, sctx);
		/*
		if(cctx->certified) {
			printf("Remove session of `%s'\n", cctx->username);
			tree_remove(sctx->sess_tab, cctx->username);
		}
		printf("Remove context of `%s'\n", cctx->username);
		free(cctx);
		bufferevent_free(bev);
		printf("Close sock fd %d\n\n", bufferevent_getfd(bev));
		*/
	}
}
