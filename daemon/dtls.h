#ifndef _DTLS_H_
#define _DTLS_H_



#include <openssl/x509.h>

#include "str.h"




enum setup_value {
	SETUP_UNKNOWN = 0,
	SETUP_ACTPASS,
	SETUP_ACTIVE,
	SETUP_PASSIVE,
	SETUP_HOLDCONN,
};


struct dtls_hash_func {
	const char *name;
	unsigned int num_bytes;
	unsigned int (*__func)(unsigned char *, X509 *);
};



int dtls_init();

const struct dtls_hash_func *dtls_find_hash_func(const str *);




#define dtls_hash(o, h, c) __dtls_hash(o, sizeof(o), h, c)
static inline void __dtls_hash(unsigned char *out, unsigned int buflen,
		const struct dtls_hash_func *hf, X509 *cert)
{
	unsigned int n;

	assert(buflen >= hf->num_bytes);
	n = hf->__func(out, cert);
	assert(n == hf->num_bytes);
}




#endif
