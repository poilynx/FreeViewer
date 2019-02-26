#ifndef _ISSUE_H_
#define _ISSUE_H_
#include <stddef.h>
#include <openssl/ssl.h>

typedef struct issue_template_st issue_template_t;

void issue_init();

void issue_destroy();

issue_template_t* issue_template_new(const char* cakey, const char* cafile, const char* country, const char* org, int bits);

void issue_template_free(issue_template_t *tpl);

int issue_sign(issue_template_t *tpl, const char* cn, EVP_PKEY **key, X509 **cert);

size_t issue_crt_to_pem(X509 *crt, uint8_t **pemptr);

size_t issue_key_to_pem(EVP_PKEY *key, uint8_t **pemptr);
#endif
