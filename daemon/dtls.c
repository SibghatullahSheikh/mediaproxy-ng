#include "dtls.h"

#include <stdio.h>
#include <string.h>
#include <glib.h>

#include "str.h"



static const struct dtls_hash_func hash_funcs[] = {
	{
		.name					= "sha-1",
		.num_bytes				= 160 / 8,
	},
	{
		.name					= "sha-224",
		.num_bytes				= 224 / 8,
	},
	{
		.name					= "sha-256",
		.num_bytes				= 256 / 8,
	},
	{
		.name					= "sha-384",
		.num_bytes				= 384 / 8,
	},
	{
		.name					= "sha-512",
		.num_bytes				= 512 / 8,
	},
};

const int num_hash_funcs = G_N_ELEMENTS(hash_funcs);




const struct dtls_hash_func *dtls_find_hash_func(const str *s) {
	int i;
	const struct dtls_hash_func *hf;

	for (i = 0; i < num_hash_funcs; i++) {
		hf = &hash_funcs[i];
		if (strlen(hf->name) != s->len)
			continue;
		if (!strncasecmp(s->s, hf->name, s->len))
			return hf;
	}

	return NULL;
}
