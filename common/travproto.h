#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_
#include <stdint.h>

#define TRAV_SERVER_PORT 6363
#define TRAV_CLIENT_PORT 6366

#pragma pack(push,1)

typedef struct {
	uint16_t length;
	uint8_t data[0];
} trav_raw_data_t;

typedef struct {
	uint32_t ipaddr;
	uint16_t port;
} trav_address_t;

typedef char trav_username_t[24];
#pragma pack(pop)

#define TRAV_ERR_SUCCESS		0
#define TRAV_ERR_UNKNOW			1
#define TRAV_ERR_USER_NOT_FOUND		2
#define TRAV_ERR_NO_CERT		3

/* =========================== */
/* client -> server */

#define TRAV_MSG_REGISTER	1
/*
 * trav_username_t hintname;
 */

#define TRAV_MSG_SIGNIN		2
#define TRAV_MSG_PING		3
#define TRAV_MSG_CONNECT	4
/*
 * trav_username_t peername;
 */


#define TRAV_MSG_TRAVERSE_READY	5
/* trav_username_t */

#define TRAV_MSG_TRAVERSE_DENY	6
/* trav_username_t */


/* =========================== */
/* server -> client*/
#define TRAV_MSG_ERROR		0
/* uint8_t error */

#define TRAV_MSG_REGISTER_ERROR	1
/* uint8_t error */

#define TRAV_MSG_SIGNIN_ERROR	2
/* uint8_t error */

#define TRAV_MSG_REGISTER_OK	3
/* uint16_t	size
 * trav_username_t realname
 * trav_raw_data	key
 * trav_raw_data	cert
 */

#define TRAV_MSG_SIGNIN_OK	4

#define TRAV_MSG_TRAVERSE	5
/*
 * trav_username_t	peername;
 * trav_address_t	peeraddr;
 */

#define TRAV_MSG_ACCEPT		6
/*
 * trav_address_t peeraddr;
 */

#define TRAV_MSG_REJECT		7
/*
 * trav_address_t peeraddr;
 */

/* =========================== */
#define ACCESS_PASSWD_MAX_LENGTH 40



#endif
