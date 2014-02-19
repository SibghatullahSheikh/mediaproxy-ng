#include "dtls.h"

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <openssl/x509.h>

#include "str.h"





static unsigned int sha_1_func(unsigned char *, X509 *);
static unsigned int sha_224_func(unsigned char *, X509 *);
static unsigned int sha_256_func(unsigned char *, X509 *);
static unsigned int sha_384_func(unsigned char *, X509 *);
static unsigned int sha_512_func(unsigned char *, X509 *);




static const struct dtls_hash_func hash_funcs[] = {
	{
		.name					= "sha-1",
		.num_bytes				= 160 / 8,
		.__func					= sha_1_func,
	},
	{
		.name					= "sha-224",
		.num_bytes				= 224 / 8,
		.__func					= sha_224_func,
	},
	{
		.name					= "sha-256",
		.num_bytes				= 256 / 8,
		.__func					= sha_256_func,
	},
	{
		.name					= "sha-384",
		.num_bytes				= 384 / 8,
		.__func					= sha_384_func,
	},
	{
		.name					= "sha-512",
		.num_bytes				= 512 / 8,
		.__func					= sha_512_func,
	},
};

const int num_hash_funcs = G_N_ELEMENTS(hash_funcs);



static struct dtls_cert __dtls_cert;



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


int dtls_init() {
	X509 *x509;
	EVP_PKEY *pkey;
	BIGNUM *exponent, *serial_number;
	RSA *rsa;
	ASN1_INTEGER *asn1_serial_number;
	X509_NAME *name;

	/* key */

	pkey = EVP_PKEY_new();
	if (!pkey)
		return -1;

	exponent = BN_new();
	if (!exponent)
		return -1;

	rsa = RSA_new();
	if (!rsa)
		return -1;

	if (!BN_set_word(exponent, 0x10001))
		return -1;

	if (!RSA_generate_key_ex(rsa, 1024, exponent, NULL))
		return -1;

	if (!EVP_PKEY_assign_RSA(pkey, rsa))
		return -1;

	/* x509 cert */

	x509 = X509_new();
	if (!x509)
		return -1;

	if (!X509_set_pubkey(x509, pkey))
		return -1;

	/* serial */

	serial_number = BN_new();
	if (!serial_number)
		return -1;

	if (!BN_pseudo_rand(serial_number, 64, 0, 0))
		return -1;

	asn1_serial_number = X509_get_serialNumber(x509);
	if (!asn1_serial_number)
		return -1;

	if (!BN_to_ASN1_INTEGER(serial_number, asn1_serial_number))
		return -1;

	/* version 1 */

	if (!X509_set_version(x509, 0L))
		return -1;

	/* common name */
	name = X509_NAME_new();
	if (!name)
		return -1;

	if (!X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_UTF8,
				(unsigned char *) "mediaproxy-ng", -1, -1, 0))
		return -1;

	if (!X509_set_subject_name(x509, name))
		return -1;

	if (!X509_set_issuer_name(x509, name))
		return -1;

	/* cert lifetime XXX */

	if (!X509_gmtime_adj(X509_get_notBefore(x509), -60*60*24))
		return -1;

	if (!X509_gmtime_adj(X509_get_notAfter(x509), 60*60*24*30))
		return -1;

	/* sign it */

	if (!X509_sign(x509, pkey, EVP_sha1()))
		return -1;

	/* digest */

	__dtls_cert.fingerprint.hash_func = &hash_funcs[0];
	dtls_hash(&__dtls_cert.fingerprint, x509);

	__dtls_cert.x509 = x509;

	/* cleanup */

	BN_free(exponent);
	BN_free(serial_number);
	X509_NAME_free(name);

	return 0;
}

static unsigned int generic_func(unsigned char *o, X509 *x, const EVP_MD *md) {
	unsigned int n;
	assert(md != NULL);
	X509_digest(x, md, o, &n);
	return n;
}

static unsigned int sha_1_func(unsigned char *o, X509 *x) {
	const EVP_MD *md;
	md = EVP_sha1();
	return generic_func(o, x, md);
}
static unsigned int sha_224_func(unsigned char *o, X509 *x) {
	const EVP_MD *md;
	md = EVP_sha224();
	return generic_func(o, x, md);
}
static unsigned int sha_256_func(unsigned char *o, X509 *x) {
	const EVP_MD *md;
	md = EVP_sha256();
	return generic_func(o, x, md);
}
static unsigned int sha_384_func(unsigned char *o, X509 *x) {
	const EVP_MD *md;
	md = EVP_sha384();
	return generic_func(o, x, md);
}
static unsigned int sha_512_func(unsigned char *o, X509 *x) {
	const EVP_MD *md;
	md = EVP_sha512();
	return generic_func(o, x, md);
}


struct dtls_cert *dtls_cert() {
	return &__dtls_cert;
}
