#ifndef _DTLS_H_
#define _DTLS_H_



#include <openssl/x509.h>

#include "str.h"




struct dtls_hash_func {
	const char *name;
	unsigned int num_bytes;
	unsigned int (*__func)(unsigned char *, X509 *);
};

struct dtls_fingerprint {
	unsigned char digest[64];
	const struct dtls_hash_func *hash_func;
};

struct dtls_cert {
	struct dtls_fingerprint fingerprint;
	EVP_PKEY *pkey;
	X509 *x509;
};

struct dtls_connection {
	SSL_CTX *ssl_ctx;
	SSL *ssl;
};




int dtls_init();

const struct dtls_hash_func *dtls_find_hash_func(const str *);
struct dtls_cert *dtls_cert(void);




static inline void dtls_hash(struct dtls_fingerprint *fp, X509 *cert)
{
	unsigned int n;

	assert(sizeof(fp->digest) >= fp->hash_func->num_bytes);
	n = fp->hash_func->__func(fp->digest, cert);
	assert(n == fp->hash_func->num_bytes);
}




#endif
