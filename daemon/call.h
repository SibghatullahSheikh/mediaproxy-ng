#ifndef __CALL_H__
#define __CALL_H__




#include <sys/types.h>
#include <glib.h>
#include <time.h>
#include <pcre.h>

#include "control_tcp.h"
#include "control_udp.h"
#include "obj.h"
#include "aux.h"
#include "bencode.h"
#include "str.h"
#include "crypto.h"



#define MAX_RTP_PACKET_SIZE	8192
#define RTP_BUFFER_HEAD_ROOM	128
#define RTP_BUFFER_TAIL_ROOM	256
#define RTP_BUFFER_SIZE		(MAX_RTP_PACKET_SIZE + RTP_BUFFER_HEAD_ROOM + RTP_BUFFER_TAIL_ROOM)



struct poller;
struct control_stream;
struct call;
struct callmaster;
struct redis;
struct crypto_suite;
struct mediaproxy_srtp;
struct streamhandler;


typedef bencode_buffer_t call_buffer_t;
#define call_buffer_alloc bencode_buffer_alloc
#define call_buffer_init bencode_buffer_init
#define call_buffer_free bencode_buffer_free




enum stream_address_format {
	SAF_TCP,
	SAF_UDP,
	SAF_NG,
	SAF_ICE,
};
enum stream_direction {
	DIR_UNKNOWN = 0,
	DIR_INTERNAL,
	DIR_EXTERNAL,
};
enum call_opmode {
	OP_OFFER = 0,
	OP_ANSWER = 1,
	OP_OTHER,
};

enum transport_protocol {
	PROTO_UNKNOWN = 0,
	PROTO_RTP_AVP,
	PROTO_RTP_SAVP,
	PROTO_RTP_AVPF,
	PROTO_RTP_SAVPF,

	__PROTO_LAST
};
extern const char *transport_protocol_strings[__PROTO_LAST];

struct stats {
	u_int64_t			packets;
	u_int64_t			bytes;
	u_int64_t			errors;
};

struct udp_fd {
	int			fd;
	u_int16_t		localport;
};
struct endpoint {
	struct in6_addr		ip46;
	u_int16_t		port;
};
struct stream_params {
	unsigned int		index; /* starting with 1 */
	str			type;
	struct endpoint		rtp_endpoint;
	struct endpoint		rtcp_endpoint;
	unsigned int		consecutive_ports;
	enum transport_protocol	protocol;
	struct crypto_params	crypto;
	unsigned int		sdes_tag;
	enum stream_direction	direction[2];

	int			no_rtcp:1;
	int			implicit_rtcp:1;
	int			rtcp_mux:1;
};

struct stream_fd {
	struct obj		obj;
	struct udp_fd		fd;		/* RO */
	struct call		*call;		/* RO */
	struct packet_stream	*stream;	/* LOCK: call->master_lock */
	struct crypto_context	crypto;		/* IN direction, LOCK: stream->in_lock */
};

struct endpoint_map {
	struct endpoint		endpoint;
	GQueue			sfds;
	int			wildcard:1;
};

struct packet_stream {
	mutex_t			in_lock,
				out_lock;
	/* Both locks valid only with call->master_lock held in R.
	 * Preempted by call->master_lock held in W.
	 * If both in/out are to be locked, in_lock must be locked first. */

	struct call_media	*media;		/* RO */
	struct call		*call;		/* RO */

	struct stream_fd	*sfd;		/* LOCK: call->master_lock */
	struct packet_stream	*rtp_sink;	/* LOCK: call->master_lock */
	struct packet_stream	*rtcp_sink;	/* LOCK: call->master_lock */
	struct packet_stream	*rtcp_sibling;	/* LOCK: call->master_lock */
	const struct streamhandler *handler;	/* LOCK: in_lock */
	struct endpoint		endpoint;	/* LOCK: out_lock */
	struct endpoint		advertised_endpoint; /* RO */
	struct crypto_context	crypto;		/* OUT direction, LOCK: out_lock */

	struct stats		stats;		/* LOCK: in_lock */
	struct stats		kernel_stats;	/* LOCK: in_lock */
	time_t			last_packet;	/* LOCK: in_lock */

	/* in_lock must be held for SETTING these: */
	/* (XXX replace with atomic ops where appropriate) */
	int			rtcp:1;	
	int			implicit_rtcp:1;
	int			stun:1;	
	int			filled:1;
	int			confirmed:1;
	int			kernelized:1;
	int			no_kernel_support:1;
	int			has_handler:1;
};

/* protected by call->master_lock, except the RO elements */
struct call_media {
	struct call_monologue	*monologue;	/* RO */
	struct call		*call;		/* RO */

	unsigned int		index;		/* RO */
	str			type;		/* RO */
	enum transport_protocol	protocol;
	int			desired_family;

	str			ice_ufrag;
	str			ice_pwd;
	struct {
		struct crypto_params	params;
		unsigned int		tag;
	}			sdes_in,
				sdes_out;

	GQueue			streams; /* normally RTP + RTCP */
	GList			*endpoint_maps; /* singly linked list? XXX */

	int			asymmetric:1;
	int			send:1;
	int			receive:1;
	int			rtcp_mux:1;
};

/* half a dialogue */
/* protected by call->master_lock, except the RO elements */
struct call_monologue {
	struct call		*call;		/* RO */

	str			tag;	
	time_t			created;	/* RO */
	GHashTable		*other_tags;
	struct call_monologue	*active_dialogue;

	GQueue			medias;	
};

struct call {
	struct obj		obj;

	struct callmaster	*callmaster;	/* RO */

	mutex_t			buffer_lock;
	call_buffer_t		buffer;

	/* everything below protected by master_lock */
	rwlock_t		master_lock;
	GList			*monologues;
	GHashTable		*tags;	
	//GHashTable		*branches;
	GList			*streams;
	GList			*stream_fds; /* XXX single linked list? */

	str			callid;	
	char			redis_uuid[37];
	time_t			created;
	time_t			last_signal;
};

struct callmaster_config {
	int			kernelfd;
	unsigned int		kernelid;
	u_int32_t		ipv4;
	u_int32_t		adv_ipv4;
	struct in6_addr		ipv6;
	struct in6_addr		adv_ipv6;
	int			port_min;
	int			port_max;
	unsigned int		timeout;
	unsigned int		silent_timeout;
	struct redis		*redis;
	char			*b2b_url;
	unsigned char		tos;
};

struct callmaster;



struct callmaster *callmaster_new(struct poller *);
void callmaster_config(struct callmaster *m, struct callmaster_config *c);
void callmaster_exclude_port(struct callmaster *m, u_int16_t p);
int callmaster_has_ipv6(struct callmaster *);
void callmaster_msg_mh_src(struct callmaster *, struct msghdr *);


str *call_request_tcp(char **, struct callmaster *);
str *call_lookup_tcp(char **, struct callmaster *);
void call_delete_tcp(char **, struct callmaster *);
void calls_status_tcp(struct callmaster *, struct control_stream *);

str *call_update_udp(char **, struct callmaster *);
str *call_lookup_udp(char **, struct callmaster *);
str *call_delete_udp(char **, struct callmaster *);
str *call_query_udp(char **, struct callmaster *);

const char *call_offer_ng(bencode_item_t *, struct callmaster *, bencode_item_t *);
const char *call_answer_ng(bencode_item_t *, struct callmaster *, bencode_item_t *);
const char *call_delete_ng(bencode_item_t *, struct callmaster *, bencode_item_t *);
const char *call_query_ng(bencode_item_t *, struct callmaster *, bencode_item_t *);


void calls_dump_redis(struct callmaster *);

struct call *call_get_or_create(const str *callid, struct callmaster *m);
struct callstream *callstream_new(struct call *ca, int num);
void kernelize(struct packet_stream *);
int call_stream_address_alt(char *, struct packet_stream *, enum stream_address_format, int *);
int call_stream_address(char *, struct packet_stream *, enum stream_address_format, int *);

enum transport_protocol transport_protocol(const str *s);




static inline void *call_malloc(struct call *c, size_t l) {
	void *ret;
	mutex_lock(&c->buffer_lock);
	ret = call_buffer_alloc(&c->buffer, l);
	mutex_unlock(&c->buffer_lock);
	return ret;
}

static inline char *call_strdup_len(struct call *c, const char *s, unsigned int len) {
	char *r;
	r = call_malloc(c, len + 1);
	memcpy(r, s, len);
	r[len] = 0;
	return r;
}

static inline char *call_strdup(struct call *c, const char *s) {
	if (!s)
		return NULL;
	return call_strdup_len(c, s, strlen(s));
}
static inline str *call_str_cpy_len(struct call *c, str *out, const char *in, int len) {
	if (!in) {
		*out = STR_NULL;
		return out;
	}
	out->s = call_strdup_len(c, in, len);
	out->len = len;
	return out;
}
static inline str *call_str_cpy(struct call *c, str *out, const str *in) {
	return call_str_cpy_len(c, out, in ? in->s : NULL, in ? in->len : 0);
}
static inline str *call_str_cpy_c(struct call *c, str *out, const char *in) {
	return call_str_cpy_len(c, out, in, in ? strlen(in) : 0);
}
static inline str *call_str_dup(struct call *c, const str *in) {
	str *out;
	out = call_malloc(c, sizeof(*out));
	call_str_cpy_len(c, out, in->s, in->len);
	return out;
}
static inline str *call_str_init_dup(struct call *c, char *s) {
	str t;
	str_init(&t, s);
	return call_str_dup(c, &t);
}



#endif
