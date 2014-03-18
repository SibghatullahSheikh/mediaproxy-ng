#include "dtls.h"

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/err.h>

#include "str.h"
#include "aux.h"
#include "crypto.h"
#include "log.h"
#include "call.h"





#define DTLS_DEBUG 0

#if DTLS_DEBUG
#define __DBG(x...) mylog(LOG_DEBUG, x)
#else
#define __DBG(x...) ((void)0)
#endif





static char ciphers_str[1024];



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


static int cert_init() {
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
	dtls_fingerprint_hash(&__dtls_cert.fingerprint, x509);

	__dtls_cert.x509 = x509;
	__dtls_cert.pkey = pkey;

	/* cleanup */

	BN_free(exponent);
	BN_free(serial_number);
	X509_NAME_free(name);

	return 0;
}

int dtls_init() {
	int i;
	char *p;

	if (cert_init())
		return -1;

	p = ciphers_str;
	for (i = 0; i < num_crypto_suites; i++) {
		if (!crypto_suites[i].dtls_name)
			continue;

		p += sprintf(p, "%s:", crypto_suites[i].dtls_name);
	}

	assert(p != ciphers_str);
	assert(p - ciphers_str < sizeof(ciphers_str));

	p[-1] = '\0';

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

static int verify_callback(int ok, X509_STORE_CTX *store) {
	SSL *ssl;
	struct stream_fd *sfd;
	struct packet_stream *ps;
	struct call_media *media;
	X509 *cert;
	unsigned char fp[DTLS_MAX_DIGEST_LEN];

	ssl = X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx());
	sfd = SSL_get_app_data(ssl);
	if (sfd->dtls.ssl != ssl)
		return 0;
	ps = sfd->stream;
	if (!ps)
		return 0;
	media = ps->media;
	if (!media)
		return 0;
	if (!media->fingerprint.hash_func)
		return 0;

	cert = X509_STORE_CTX_get_current_cert(store);
	dtls_hash(media->fingerprint.hash_func, cert, fp);

	if (memcmp(media->fingerprint.digest, fp, media->fingerprint.hash_func->num_bytes)) {
		mylog(LOG_WARNING, "Peer certificate rejected - fingerprint mismatch");
		__DBG("fingerprint expected: %02x%02x%02x%02x%02x%02x%02x%02x received: %02x%02x%02x%02x%02x%02x%02x%02x",
			media->fingerprint.digest[0], media->fingerprint.digest[1],
			media->fingerprint.digest[2], media->fingerprint.digest[3],
			media->fingerprint.digest[4], media->fingerprint.digest[5],
			media->fingerprint.digest[6], media->fingerprint.digest[7], 
			fp[0], fp[1], fp[2], fp[3],
			fp[4], fp[5], fp[6], fp[7]);
		return 0;
	}

	mylog(LOG_INFO, "Peer certificate accepted");

	return 1;
}

static int try_connect(struct dtls_connection *d) {
	int ret, code;

	if (d->connected)
		return 0;

	if (d->active)
		ret = SSL_connect(d->ssl);
	else
		ret = SSL_accept(d->ssl);

	code = SSL_get_error(d->ssl, ret);

	ret = 0;
	switch (code) {
		case SSL_ERROR_NONE:
			mylog(LOG_DEBUG, "DTLS handshake successful");
			d->connected = 1;
			ret = 1;
			break;

		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			break;

		default:
			mylog(LOG_ERROR, "DTLS error: %i", code);
			ret = -1;
			break;
	}

	return ret;
}

int dtls_connection_init(struct packet_stream *ps, int active, struct dtls_cert *cert) {
	struct dtls_connection *d = &ps->sfd->dtls;
	unsigned long err;

	if (d->init)
		goto connect;

	ZERO(*d);

	d->ssl_ctx = SSL_CTX_new(active ? DTLSv1_client_method() : DTLSv1_server_method());
	if (!d->ssl_ctx)
		goto error;

	if (SSL_CTX_use_certificate(d->ssl_ctx, cert->x509) != 1)
		goto error;
	if (SSL_CTX_use_PrivateKey(d->ssl_ctx, cert->pkey) != 1)
		goto error;

	SSL_CTX_set_verify(d->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			verify_callback);
	SSL_CTX_set_verify_depth(d->ssl_ctx, 4);
	SSL_CTX_set_cipher_list(d->ssl_ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");

	if (SSL_CTX_set_tlsext_use_srtp(d->ssl_ctx, ciphers_str))
		goto error;

	d->ssl = SSL_new(d->ssl_ctx);
	if (!d->ssl)
		goto error;

	d->r_bio = BIO_new(BIO_s_mem());
	d->w_bio = BIO_new(BIO_s_mem());
	if (!d->r_bio || !d->w_bio)
		goto error;

	SSL_set_app_data(d->ssl, ps->sfd); /* XXX obj reference here? */
	SSL_set_bio(d->ssl, d->r_bio, d->w_bio);
	SSL_set_mode(d->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	d->init = 1;
	d->active = active;

connect:
	dtls(ps, NULL, NULL);

	return 0;

error:
	err = ERR_peek_last_error();
	if (d->r_bio)
		BIO_free(d->r_bio);
	if (d->w_bio)
		BIO_free(d->w_bio);
	if (d->ssl)
		SSL_free(d->ssl);
	if (d->ssl_ctx)
		SSL_CTX_free(d->ssl_ctx);
	ZERO(*d);
	mylog(LOG_ERROR, "Failed to init DTLS connection: %s", ERR_reason_error_string(err));
	return -1;
}

static int dtls_setup_crypto(struct packet_stream *ps, struct dtls_connection *d) {
	const char *err;
	SRTP_PROTECTION_PROFILE *spp;
	int i;
	const struct crypto_suite *cs;
	unsigned char keys[2 * (SRTP_MAX_MASTER_KEY_LEN + SRTP_MAX_MASTER_SALT_LEN)];
	struct crypto_params client, server;

	err = "no SRTP protection profile negotiated";
	spp = SSL_get_selected_srtp_profile(d->ssl);
	if (!spp)
		goto error;

	for (i = 0; i < num_crypto_suites; i++) {
		cs = &crypto_suites[i];
		if (!cs->dtls_name)
			continue;
		if (!strcmp(cs->dtls_name, spp->name))
			goto found;
	}

	err = "unknown SRTP protection profile negotiated";
	goto error;

found:
	i = SSL_export_keying_material(d->ssl, keys, sizeof(keys), "EXTRACTOR-dtls_srtp",
			strlen("EXTRACTOR-dtls_srtp"), NULL, 0, 0);
	err = "failed to export keying material";
	if (i != 1)
		goto error;

	/* got everything XXX except MKI */
	ZERO(client);
	ZERO(server);
	i = 0;

	client.crypto_suite = server.crypto_suite = cs;

	memcpy(client.master_key, &keys[i], cs->master_key_len);
	i += cs->master_key_len;
	memcpy(server.master_key, &keys[i], cs->master_key_len);
	i += cs->master_key_len;
	memcpy(client.master_salt, &keys[i], cs->master_salt_len);
	i += cs->master_salt_len;
	memcpy(server.master_salt, &keys[i], cs->master_salt_len);

	__DBG("SRTP keys negotiated: "
			"c-m: %02x%02x%02x%02x%02x%02x%02x%02x "
			"c-s: %02x%02x%02x%02x%02x%02x%02x%02x "
			"s-m: %02x%02x%02x%02x%02x%02x%02x%02x "
			"s-s: %02x%02x%02x%02x%02x%02x%02x%02x",
			client.master_key[0], client.master_key[1], client.master_key[2], client.master_key[3],
			client.master_key[4], client.master_key[5], client.master_key[6], client.master_key[7],
			client.master_salt[0], client.master_salt[1], client.master_salt[2], client.master_salt[3],
			client.master_salt[4], client.master_salt[5], client.master_salt[6], client.master_salt[7],
			server.master_key[0], server.master_key[1], server.master_key[2], server.master_key[3],
			server.master_key[4], server.master_key[5], server.master_key[6], server.master_key[7],
			server.master_salt[0], server.master_salt[1], server.master_salt[2], server.master_salt[3],
			server.master_salt[4], server.master_salt[5], server.master_salt[6], server.master_salt[7]);

	mylog(LOG_INFO, "DTLS-SRTP successfully negotiated");

	if (d->active) {
		/* we're the client */
		crypto_init(&ps->crypto, &client);
		crypto_init(&ps->sfd->crypto, &server);
	}
	else {
		/* we're the server */
		crypto_init(&ps->crypto, &server);
		crypto_init(&ps->sfd->crypto, &client);
	}

	return 0;

error:
	if (!spp)
		mylog(LOG_ERROR, "Failed to set up SRTP after DTLS negotiation: %s", err);
	else
		mylog(LOG_ERROR, "Failed to set up SRTP after DTLS negotiation: %s (profile \"%s\")",
				err, spp->name);
	return -1;
}

int dtls(struct packet_stream *ps, const str *s, struct sockaddr_in6 *fsin) {
	struct dtls_connection *d = &ps->sfd->dtls;
	int ret;
	unsigned char buf[0x10000], ctrl[256];
	struct msghdr mh;
	struct iovec iov;
	struct sockaddr_in6 sin;

	if (s)
		__DBG("dtls packet input: len %u %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			s->len,
			(unsigned char) s->s[0], (unsigned char) s->s[1], (unsigned char) s->s[2], (unsigned char) s->s[3],
			(unsigned char) s->s[4], (unsigned char) s->s[5], (unsigned char) s->s[6], (unsigned char) s->s[7],
			(unsigned char) s->s[8], (unsigned char) s->s[9], (unsigned char) s->s[10], (unsigned char) s->s[11],
			(unsigned char) s->s[12], (unsigned char) s->s[13], (unsigned char) s->s[14], (unsigned char) s->s[15]);

	if (d->connected)
		return 0;

	if (s)
		BIO_write(d->r_bio, s->s, s->len);

	ret = try_connect(d);
	if (ret == -1) {
		/* fatal error */
		d->init = 0;
		/* XXX ?? */
		return 0;
	}
	else if (ret == 1) {
		/* connected! */
		if (dtls_setup_crypto(ps, d))
			/* XXX ?? */ ;
	}

	ret = BIO_ctrl_pending(d->w_bio);
	if (ret <= 0)
		return 0;

	if (ret > sizeof(buf)) {
		mylog(LOG_ERROR, "BIO buffer overflow");
		BIO_reset(d->w_bio);
		return 0;
	}

	ret = BIO_read(d->w_bio, buf, ret);
	if (ret <= 0)
		return 0;

	__DBG("dtls packet output: len %u %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		ret,
		buf[0], buf[1], buf[2], buf[3],
		buf[4], buf[5], buf[6], buf[7],
		buf[8], buf[9], buf[10], buf[11],
		buf[12], buf[13], buf[14], buf[15]);

	if (!fsin) {
		ZERO(sin);
		sin.sin6_family = AF_INET6;
		sin.sin6_addr = ps->endpoint.ip46;
		sin.sin6_port = htons(ps->endpoint.port);
		fsin = &sin;
	}

	ZERO(mh);
	mh.msg_control = ctrl;
	mh.msg_controllen = sizeof(ctrl);
	mh.msg_name = fsin;
	mh.msg_namelen = sizeof(*fsin);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;

	ZERO(iov);
	iov.iov_base = buf;
	iov.iov_len = ret;

	callmaster_msg_mh_src(ps->call->callmaster, &mh);

	sendmsg(ps->sfd->fd.fd, &mh, 0);

	return 0;
}
