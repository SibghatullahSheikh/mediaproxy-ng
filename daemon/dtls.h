#ifndef _DTLS_H_
#define _DTLS_H_



#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

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
	BIO *r_bio, *w_bio;
};




int dtls_init();

const struct dtls_hash_func *dtls_find_hash_func(const str *);
struct dtls_cert *dtls_cert(void);

int dtls_connection_init(struct dtls_connection *d, int active, struct dtls_cert *cert);




static inline void dtls_hash(struct dtls_fingerprint *fp, X509 *cert) {
	unsigned int n;

	assert(sizeof(fp->digest) >= fp->hash_func->num_bytes);
	n = fp->hash_func->__func(fp->digest, cert);
	assert(n == fp->hash_func->num_bytes);
}

static inline int is_dtls(const str *s) {
	const unsigned char *b = (const void *) s->s;

	if (s->len < 1)
		return 0;
	/* RFC 5764, 5.1.2 */
	if (b[0] >= 20 && b[0] <= 63)
		return 1;

	return 0;
}




#endif
