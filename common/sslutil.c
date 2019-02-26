#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <openssl/ssl.h>

int load_key_pair(const char *key_path, EVP_PKEY **key, const char *crt_path, X509 **crt) {
	BIO *bio = NULL;
	*crt = NULL;
	*key = NULL;

	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, crt_path)) 
		goto err;
	if((*crt = PEM_read_bio_X509(bio, NULL, NULL, NULL)) == NULL)
		goto err;
	BIO_free_all(bio);

	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, key_path))
		goto err;
	if((*key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)) == NULL)
		goto err;
	BIO_free_all(bio);

	return 0;

err:
	if(*crt) X509_free(*crt);
	BIO_free_all(bio);
	*crt = NULL;
	*key = NULL;

	return 1;
}

int save_key(EVP_PKEY *key, const char *key_path) {
	BIO *bio =NULL;
	bio = BIO_new(BIO_s_file());
	if(BIO_write_filename(bio, (void*)key_path) != 1) {
		BIO_free(bio);
		printf("BIO_write_filename error\n");
	}
	RSA *rsa;
	//rsa = EVP_PKEY_get0_RSA(key);//FIXME:
	rsa = EVP_PKEY_get1_RSA(key);
	if(PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL ,NULL) != 1) {
		printf("PEM_write_bio_PrivateKey error\n");
		BIO_free(bio);
		return -1;
	}
	RSA_free(rsa);
	BIO_free(bio);
	return 0;
}

int save_cert(X509 *cert, const char *cert_path) {
	BIO *bio = NULL;
	bio = BIO_new(BIO_s_file());
	if(BIO_write_filename(bio, (void*)cert_path) != 1) {
		printf("BIO_write_filename error\n");
		BIO_free(bio);
		return -1;
	}
	if(PEM_write_bio_X509(bio, cert) != 1) {
		printf("PEM_write_bio_RSAPublicKey error\n");
		BIO_free(bio);
		return -1;
	}
	BIO_free(bio);
	return 0;
}
EVP_PKEY *pem2key(unsigned char *pem, size_t size) {
	printf("pem2key\n");
	BIO *bio;
	EVP_PKEY *key = NULL;
	assert(pem);
	/*
	bio = BIO_new(BIO_s_mem());
	if(BIO_write(bio, pem, size) <= 0) {
		printf("BIO_write error\n");
		BIO_free(bio);
		return NULL;
	}
	*/
	//for(int i=0;i<size;i++) printf("%c", pem[i]);
	bio = BIO_new_mem_buf(pem, -1);
	if((PEM_read_bio_PrivateKey(bio, &key, NULL, NULL)) == NULL) {
	//if(PEM_read_bio_PrivateKey(bio, &key, NULL, NULL) != NULL) {
		printf("PEM_read_bio_PrivateKey error\n");
		BIO_free(bio);
		return NULL;
	}
	BIO_free(bio);
	printf("pem2key over\n");
	printf("k = %p\n", key);
	return key;
}

X509 *pem2cert(unsigned char *pem, size_t size) {
	BIO *bio;
	X509 *cert = NULL;
	assert(pem);
	/*
	bio = BIO_new(BIO_s_mem());
	if(BIO_write(bio, pem, size) <= 0) {
		printf("BIO_write error\n");
		BIO_free(bio);
		return NULL;
	}
	*/
	bio = BIO_new_mem_buf(pem, -1);
	if(PEM_read_bio_X509(bio, &cert, NULL, NULL) == NULL) {
		printf("PEM_read_bio_X509 error\n");
		BIO_free(bio);
		return NULL;
	}
	BIO_free(bio);
	return cert;

}
int sslutil_cert_get_CN(X509 *cert, char *buf, size_t size) {
	if ( cert == NULL )
		return -1;

	int lastpos = -1, len;

	X509_NAME *subj = X509_get_subject_name(cert);
	X509_NAME_ENTRY *e;

	lastpos = X509_NAME_get_index_by_NID(subj, NID_commonName, lastpos);
	assert(lastpos != -1);

	e = X509_NAME_get_entry(subj, lastpos);
	ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
	///char *str = (char*)ASN1_STRING_get0_data(d);//FIXME:
	char *str = (char*)ASN1_STRING_get0_data(d);
	len = ASN1_STRING_length(d);
	if(len >= size) {
		X509_free(cert);
		return -1;
	}
	memcpy(buf, str, len);
	buf[len] = '\0';
	///free(str); !!!! Internal pointer, do not free it !!!!
	//X509_free(cert); ///!!! not free it
	return 0;
}

int sslutil_ssl_get_local_CN(SSL *ssl, char *buf, size_t size) {
	X509 *cert = SSL_get_certificate(ssl);
	return sslutil_cert_get_CN(cert, buf, size);
}

int sslutil_ssl_get_peer_CN(SSL *ssl, char *buf, size_t size) {
	X509 *cert = SSL_get_peer_certificate(ssl);
	return sslutil_cert_get_CN(cert, buf, size);
}

int sslutil_get_local_CN(SSL *ssl, int local, char *buf, size_t size);
int sslutil_get_peer_CN(SSL *ssl, int local, char *buf, size_t size);

char* sslutil_cert_get_serial_number(X509 *cert) {
	ASN1_INTEGER *aint = X509_get_serialNumber(cert);
	//X509_free(cert);

	char *snum = malloc(aint->length*2 + 1);
	snum[aint->length] = '\0';

	//printf("Peer serial number: ");
	for(int i=0;i<aint->length;i++) {
		//printf("%02hhX:", aint->data[i]);
		sprintf(snum + i*2, "%02hhX", aint->data[i]);
	}
	//putchar('\n');
	return snum;
}

/*
int main() {
	//SSL_library_init();
	OpenSSL_add_all_algorithms();
	X509 *cert;
	EVP_PKEY *key;
	if(load_key_pair("certs/root.key" ,&key, "certs/root.cert", &cert)) {
		printf("err\n");
		return 1;
	}
	
	//save_cert(cert, "a.cert");
}
*/
