#ifndef _SSLUTIL_H_
#define _SSLUTIL_H_
#include <openssl/ssl.h>
int load_key_pair(const char *key_path, EVP_PKEY **key, const char *crt_path, X509 **crt);
int save_key(EVP_PKEY *key, const char *key_path);
int save_cert(X509 *cert, const char *cert_path);
EVP_PKEY *pem2key(unsigned char *pem, size_t size);
X509 *pem2cert(unsigned char *pem, size_t size);
int sslutil_cert_get_CN(X509 *cert, char *buf, size_t size);
int sslutil_ssl_get_local_CN(SSL *ssl, char *buf, size_t size);
int sslutil_ssl_get_peer_CN(SSL *ssl, char *buf, size_t size);

char* sslutil_cert_get_serial_number(X509 *ssl);
#endif
