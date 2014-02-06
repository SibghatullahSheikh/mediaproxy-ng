#ifndef _DTLS_H_
#define _DTLS_H_



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
};



const struct dtls_hash_func *dtls_find_hash_func(const str *);




#endif
