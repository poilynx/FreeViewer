#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

//#define CRYPTO_MDEBUG 1
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include "issue.h"


#define REQ_DN_C "CN"
#define REQ_DN_ST ""
#define REQ_DN_L ""
#define REQ_DN_O "jmpesp.cc"
#define REQ_DN_OU ""
//#define REQ_DN_CN "VNF Application"

#if 0
/* Adds time to the memory checking information */
#define V_CRYPTO_MDEBUG_TIME 0x1
/* Adds thread number to the memory checking information */
#define V_CRYPTO_MDEBUG_THREAD 0x2
#define V_CRYPTO_MDEBUG_ALL (V_CRYPTO_MDEBUG_TIME | V_CRYPTO_MDEBUG_THREAD)
#endif

struct issue_template_st{
	EVP_PKEY *cakey;
	X509 *ca;
	X509_NAME *name;
	int bits;
};



static void cleanup_crypto(void);
//static void crt_to_pem(X509 *crt, uint8_t **crt_bytes, size_t *crt_size);
static int generate_key_csr(X509_NAME *name, int bits, EVP_PKEY **key, X509_REQ **req);
static int generate_set_random_serial(X509 *crt);
static int generate_signed_key_pair(X509_NAME *name, int bits, EVP_PKEY *ca_key, X509 *ca_crt, EVP_PKEY **key, X509 **crt);
static void initialize_crypto(void);
//static void key_to_pem(EVP_PKEY *key, uint8_t **key_bytes, size_t *key_size);
static int load_ca(const char *ca_key_path, EVP_PKEY **ca_key, const char *ca_crt_path, X509 **ca_crt);
#if 0
static void print_bytes(uint8_t *data, size_t size);
#endif

static void cleanup_crypto() {
	CRYPTO_cleanup_all_ex_data();
	//ERR_remove_thread_state(NULL);
	ERR_free_strings();
	//CRYPTO_mem_leaks_fp(stderr);
}
static int generate_signed_key_pair(X509_NAME *name, int bits, EVP_PKEY *ca_key, X509 *ca_crt, EVP_PKEY **key, X509 **crt) {
	/* Generate the private key and corresponding CSR. */
	X509_REQ *req = NULL;
	if (!generate_key_csr(name, bits, key, &req)) {
		fprintf(stderr, "Failed to generate key and/or CSR!\n");
		return 0;
	}

	/* Sign with the CA. */
	*crt = X509_new();
	if (!*crt) goto err;

	X509_set_version(*crt, 2); /* Set version to X509v3 */

	/* Generate random 20 byte serial. */
	if (!generate_set_random_serial(*crt)) goto err;

	/* Set issuer to CA's subject. */
	X509_set_issuer_name(*crt, X509_get_subject_name(ca_crt));

	/* Set validity of certificate to 2 years. */
	X509_gmtime_adj(X509_get_notBefore(*crt), 0);
	X509_gmtime_adj(X509_get_notAfter(*crt), (long)2*365*3600);

	/* Get the request's subject and just use it (we don't bother checking it since we generated
	 * it ourself). Also take the request's public key. */
	X509_set_subject_name(*crt, X509_REQ_get_subject_name(req));
	EVP_PKEY *req_pubkey = X509_REQ_get_pubkey(req);
	X509_set_pubkey(*crt, req_pubkey);
	EVP_PKEY_free(req_pubkey);

	/* Now perform the actual signing with the CA. */
	if (X509_sign(*crt, ca_key, EVP_sha256()) == 0) goto err;

	X509_REQ_free(req);
	return 1;
err:
	EVP_PKEY_free(*key);
	X509_REQ_free(req);
	X509_free(*crt);
	return 0;
}

static int generate_key_csr(X509_NAME *name, int bits, EVP_PKEY **key, X509_REQ **req) {
	*key = EVP_PKEY_new();
	if (!*key) goto err;
	*req = X509_REQ_new();
	if (!*req) goto err;

	//RSA *rsa = RSA_generate_key(RSA_KEY_BITS, RSA_F4, NULL, NULL);
	RSA *rsa = RSA_new();
	BIGNUM* bne = BN_new();
	BN_set_word(bne,RSA_F4);
	if(RSA_generate_key_ex(rsa, bits, bne, NULL) == 0)
		goto err;
	
	if (!EVP_PKEY_assign_RSA(*key, rsa)) goto err;

	X509_REQ_set_pubkey(*req, *key);

	X509_REQ_set_subject_name(*req, name);

	/* Self-sign the request to prove that we posses the key. */
	if (!X509_REQ_sign(*req, *key, EVP_sha256())) goto err;
	return 1;
err:
	EVP_PKEY_free(*key);
	X509_REQ_free(*req);
	return 0;
}

static int generate_set_random_serial(X509 *crt) {
	/* Generates a 20 byte random serial number and sets in certificate. */
	unsigned char serial_bytes[20];
	if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1) return 0;
	serial_bytes[0] &= 0x7f; /* Ensure positive serial! */
	BIGNUM *bn = BN_new();
	BN_bin2bn(serial_bytes, sizeof(serial_bytes), bn);
	ASN1_INTEGER *serial = ASN1_INTEGER_new();
	BN_to_ASN1_INTEGER(bn, serial);

	X509_set_serialNumber(crt, serial); // Set serial.

	ASN1_INTEGER_free(serial);
	BN_free(bn);
	return 1;
}

static void initialize_crypto() {
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	//OPENSSL_config(NULL);
	
	//CRYPTO_malloc_debug_init(); 
	//CRYPTO_malloc_init(); 
	CRYPTO_set_mem_functions((void*)malloc, (void*)realloc, (void*)free);
	//CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL); 
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
}


static int load_ca(const char *ca_key_path, EVP_PKEY **ca_key, const char *ca_crt_path, X509 **ca_crt) {
	BIO *bio = NULL;
	*ca_crt = NULL;
	*ca_key = NULL;

	/* Load CA public key. */
	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, ca_crt_path)) goto err;
	*ca_crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (!*ca_crt) goto err;
	BIO_free_all(bio);

	/* Load CA private key. */
	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, ca_key_path)) goto err;
	*ca_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (!ca_key) goto err;
	BIO_free_all(bio);
	return 1;
err:
	BIO_free_all(bio);
	X509_free(*ca_crt);
	EVP_PKEY_free(*ca_key);
	return 0;
}

/*
static void print_bytes(uint8_t *data, size_t size) {
	for (size_t i = 0; i < size; i++) {
		printf("%c", data[i]);
	}
}
*/
void issue_init() {
	initialize_crypto();
}

void issue_destroy() {
	cleanup_crypto();
}

issue_template_t* issue_template_new(const char* cakey, const char* cafile, const char* country, const char* org, int bits) {
	issue_template_t * tpl = malloc(sizeof(issue_template_t));
	assert(tpl);
	if(load_ca(cakey, &tpl->cakey, cafile, &tpl->ca) == 0) {
		printf("load_ca error");
		free(tpl);
		return NULL;
	}
	/* Set the DN of the request. */
	tpl->name = X509_NAME_new();//X509_REQ_get_subject_name(*req);
	X509_NAME_add_entry_by_txt(tpl->name, "C", MBSTRING_ASC, (const unsigned char*)country, -1, -1, 0);
	//X509_NAME_add_entry_by_txt(tpl->name, "ST", MBSTRING_ASC, (const unsigned char*)REQ_DN_ST, -1, -1, 0);
	//X509_NAME_add_entry_by_txt(tpl->name, "L", MBSTRING_ASC, (const unsigned char*)REQ_DN_L, -1, -1, 0);
	X509_NAME_add_entry_by_txt(tpl->name, "O", MBSTRING_ASC, (const unsigned char*)org, -1, -1, 0);
	//X509_NAME_add_entry_by_txt(tpl->name, "OU", MBSTRING_ASC, (const unsigned char*)REQ_DN_OU, -1, -1, 0);
	//X509_NAME_add_entry_by_txt(tpl->name, "CN", MBSTRING_ASC, (const unsigned char*)cn/*(const unsigned char*)REQ_DN_CN*/, -1, -1, 0);

	tpl->bits = bits;
	return tpl;
	
}

void issue_template_free(issue_template_t *tpl) {
	X509_free(tpl->ca);
	X509_NAME_free(tpl->name);
	EVP_PKEY_free(tpl->cakey);
	free(tpl);
}

int issue_sign(issue_template_t *tpl, const char* cn, EVP_PKEY **key, X509 **cert) {

	int ret;
	assert(tpl);
	assert(cn);
	assert(key);
	assert(cert);
	X509_NAME_add_entry_by_txt(tpl->name, "CN", MBSTRING_ASC, (const unsigned char*)cn, -1, -1, 2);
	ret = generate_signed_key_pair(tpl->name, tpl->bits, tpl->cakey, tpl->ca, key, cert);
	if(ret == 0) {
		X509_NAME_delete_entry(tpl->name, 0);
		return -1;
	}
	X509_NAME_delete_entry(tpl->name, 2);
	return 0;
}

/* Convert signed certificate to PEM format. */
size_t issue_crt_to_pem(X509 *crt, uint8_t **pemptr) {
	size_t crt_size;
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio, crt);
	crt_size = BIO_pending(bio);
	*pemptr= (uint8_t *)malloc(crt_size + 1);
	BIO_read(bio, *pemptr, crt_size);
	BIO_free_all(bio);
	return crt_size;
}

/* Convert private key to PEM format. */
size_t issue_key_to_pem(EVP_PKEY *key, uint8_t **pemptr) {
	size_t key_size;
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
	key_size = BIO_pending(bio);
	*pemptr= (uint8_t *)malloc(key_size + 1);
	BIO_read(bio, *pemptr, key_size);
	BIO_free_all(bio);
	return key_size;
}




#if 0
int main() {
	X509 *cert;
	EVP_PKEY *key;
	issue_init();
	issue_template_t *tpl = issue_template_new("../certs/root.key", "../certs/root.cert", "CN", "Jmpesp", 2048);
	assert(tpl);
	if(issue_sign(tpl, "hello", &key, &cert) != 0) {
		printf("sign error\n");
	}
	if(issue_sign(tpl, "world", &key, &cert) != 0) {
		printf("sign error\n");
	}
	uint8_t *key_bytes = NULL;
	uint8_t *crt_bytes = NULL;
	size_t key_size = issue_key_to_pem(key, &key_bytes);
	size_t crt_size = issue_crt_to_pem(cert, &crt_bytes);


	/* Print key and certificate. */
	print_bytes(key_bytes, key_size);
	print_bytes(crt_bytes, crt_size);

	issue_template_free(tpl);
	issue_destroy();
	return 0;
}
// gcc issue.c -lcrypto && ./a.out>a.pem && openssl x509 -in a.pem -noout -subject
#endif
