#include "call.h"

#include <stdio.h>
#include <unistd.h>
#include <glib.h>
#include <stdlib.h>
#include <pcre.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <xmlrpc_client.h>
#include <sys/wait.h>

#include "poller.h"
#include "aux.h"
#include "log.h"
#include "kernel.h"
#include "control_tcp.h"
#include "streambuf.h"
#include "redis.h"
#include "xt_MEDIAPROXY.h"
#include "bencode.h"
#include "sdp.h"
#include "str.h"
#include "stun.h"
#include "rtcp.h"
#include "rtp.h"



#ifdef __DEBUG
#define DBG(x...) mylog(LOG_DEBUG, x)
#else
#define DBG(x...) ((void)0)
#endif

#define LOG_PREFIX_C "["STR_FORMAT"] "
#define LOG_PREFIX_CI "["STR_FORMAT" - "STR_FORMAT"] "
#define LOG_PARAMS_C(c) STR_FMT(&(c)->callid)
#define LOG_PARAMS_CI(c) STR_FMT(&(c)->callid), STR_FMT0(log_info)



static __thread const str *log_info;




typedef int (*rewrite_func)(str *, struct packet_stream *);

/* also serves as array index for callstream->peers[] */
struct iterator_helper {
	GSList			*del;
	struct packet_stream	*ports[0x10000];
};
struct xmlrpc_helper {
	GStringChunk		*c;
	char			*url;
	GSList			*tags;
};


struct callmaster {
	struct obj		obj;

	rwlock_t		hashlock;
	GHashTable		*callhash;

	mutex_t			portlock;
	u_int16_t		lastport;
	BIT_ARRAY_DECLARE(ports_used, 0x10000);

	mutex_t			statspslock;
	struct stats		statsps;	/* per second stats, running timer */
	mutex_t			statslock;
	struct stats		stats;		/* copied from statsps once a second */

	struct poller		*poller;
	pcre			*info_re;
	pcre_extra		*info_ree;
	pcre			*streams_re;
	pcre_extra		*streams_ree;

	struct callmaster_config conf;
};

struct call_stats {
	time_t		newest;
	struct stats	totals[4]; /* rtp in, rtcp in, rtp out, rtcp out */
};

struct streamhandler_io {
	rewrite_func	rtp;
	rewrite_func	rtcp;
	int		(*kernel)(struct mediaproxy_srtp *, struct packet_stream *);
};
struct streamhandler {
	const struct streamhandler_io	*in;
	const struct streamhandler_io	*out;
};

#if 0
static char *rtp_codecs[] = {
	[0]	= "G711u",
	[1]	= "1016",
	[2]	= "G721",
	[3]	= "GSM",
	[4]	= "G723",
	[5]	= "DVI4",
	[6]	= "DVI4",
	[7]	= "LPC",
	[8]	= "G711a",
	[9]	= "G722",
	[10]	= "L16",
	[11]	= "L16",
	[14]	= "MPA",
	[15]	= "G728",
	[18]	= "G729",
	[25]	= "CelB",
	[26]	= "JPEG",
	[28]	= "nv",
	[31]	= "H261",
	[32]	= "MPV",
	[33]	= "MP2T",
	[34]	= "H263",
};
#endif
const char *transport_protocol_strings[__PROTO_LAST] = {
	[PROTO_RTP_AVP]		= "RTP/AVP",
	[PROTO_RTP_SAVP]	= "RTP/SAVP",
	[PROTO_RTP_AVPF]	= "RTP/AVPF",
	[PROTO_RTP_SAVPF]	= "RTP/SAVPF",
};




static void determine_handler(struct packet_stream *in, struct packet_stream *out);

static int __k_null(struct mediaproxy_srtp *s, struct packet_stream *);
static int __k_srtp_encrypt(struct mediaproxy_srtp *s, struct packet_stream *);
static int __k_srtp_decrypt(struct mediaproxy_srtp *s, struct packet_stream *);

static int call_avp2savp_rtp(str *s, struct packet_stream *);
static int call_savp2avp_rtp(str *s, struct packet_stream *);
static int call_avp2savp_rtcp(str *s, struct packet_stream *);
static int call_savp2avp_rtcp(str *s, struct packet_stream *);
static int call_avpf2avp_rtcp(str *s, struct packet_stream *);
//static int call_avpf2savp_rtcp(str *s, struct packet_stream *);
static int call_savpf2avp_rtcp(str *s, struct packet_stream *);
//static int call_savpf2savp_rtcp(str *s, struct packet_stream *);


/* ********** */

static const struct streamhandler_io __shio_noop = {
	.kernel		= __k_null,
};
static const struct streamhandler_io __shio_decrypt = {
	.kernel		= __k_srtp_decrypt,
	.rtp		= call_savp2avp_rtp,
	.rtcp		= call_savp2avp_rtcp,
};
static const struct streamhandler_io __shio_encrypt = {
	.kernel		= __k_srtp_encrypt,
	.rtp		= call_avp2savp_rtp,
	.rtcp		= call_avp2savp_rtcp,
};
static const struct streamhandler_io __shio_avpf_strip = {
	.kernel		= __k_null,
	.rtcp		= call_avpf2avp_rtcp,
};
static const struct streamhandler_io __shio_decrypt_avpf_strip = {
	.kernel		= __k_srtp_decrypt,
	.rtp		= call_savp2avp_rtp,
	.rtcp		= call_savpf2avp_rtcp,
};

/* ********** */

static const struct streamhandler __sh_noop = {
	.in		= &__shio_noop,
	.out		= &__shio_noop,
};
static const struct streamhandler __sh_savp2avp = {
	.in		= &__shio_decrypt,
	.out		= &__shio_noop,
};
static const struct streamhandler __sh_avp2savp = {
	.in		= &__shio_noop,
	.out		= &__shio_encrypt,
};
static const struct streamhandler __sh_avpf2avp = {
	.in		= &__shio_avpf_strip,
	.out		= &__shio_noop,
};
static const struct streamhandler __sh_avpf2savp = {
	.in		= &__shio_avpf_strip,
	.out		= &__shio_encrypt,
};
static const struct streamhandler __sh_savpf2avp = {
	.in		= &__shio_decrypt_avpf_strip,
	.out		= &__shio_noop,
};
static const struct streamhandler __sh_savpf2savp = {
	.in		= &__shio_decrypt_avpf_strip,
	.out		= &__shio_encrypt,
};

/* ********** */

static const struct streamhandler *__sh_matrix_in_rtp_avp[__PROTO_LAST] = {
	[PROTO_RTP_AVP]		= &__sh_noop,
	[PROTO_RTP_AVPF]	= &__sh_noop,
	[PROTO_RTP_SAVP]	= &__sh_avp2savp,
	[PROTO_RTP_SAVPF]	= &__sh_avp2savp,
};
static const struct streamhandler *__sh_matrix_in_rtp_avpf[__PROTO_LAST] = {
	[PROTO_RTP_AVP]		= &__sh_avpf2avp,
	[PROTO_RTP_AVPF]	= &__sh_noop,
	[PROTO_RTP_SAVP]	= &__sh_avpf2savp,
	[PROTO_RTP_SAVPF]	= &__sh_avp2savp,
};
static const struct streamhandler *__sh_matrix_in_rtp_savp[__PROTO_LAST] = {
	[PROTO_RTP_AVP]		= &__sh_savp2avp,
	[PROTO_RTP_AVPF]	= &__sh_savp2avp,
	[PROTO_RTP_SAVP]	= &__sh_noop,
	[PROTO_RTP_SAVPF]	= &__sh_noop,
};
static const struct streamhandler *__sh_matrix_in_rtp_savpf[__PROTO_LAST] = {
	[PROTO_RTP_AVP]		= &__sh_savpf2avp,
	[PROTO_RTP_AVPF]	= &__sh_savp2avp,
	[PROTO_RTP_SAVP]	= &__sh_savpf2savp,
	[PROTO_RTP_SAVPF]	= &__sh_noop,
};

/* ********** */

static const struct streamhandler **__sh_matrix[__PROTO_LAST] = {
	[PROTO_RTP_AVP]		= __sh_matrix_in_rtp_avp,
	[PROTO_RTP_AVPF]	= __sh_matrix_in_rtp_avpf,
	[PROTO_RTP_SAVP]	= __sh_matrix_in_rtp_savp,
	[PROTO_RTP_SAVPF]	= __sh_matrix_in_rtp_savpf,
};

/* ********** */

static const struct mediaproxy_srtp __mps_null = {
	.cipher			= MPC_NULL,
	.hmac			= MPH_NULL,
};






static void call_destroy(struct call *);
static void unkernelize(struct packet_stream *);
static void ng_call_stats(struct call *call, const str *fromtag, const str *totag, bencode_item_t *output);




/* called lock-free */
static void stream_fd_closed(int fd, void *p, uintptr_t u) {
	struct stream_fd *sfd = p;
	struct call *c;
	int i;
	socklen_t j;

	assert(sfd->fd.fd == fd);
	c = sfd->call;
	if (!c)
		return;

	j = sizeof(i);
	getsockopt(fd, SOL_SOCKET, SO_ERROR, &i, &j);
	mylog(LOG_WARNING, LOG_PREFIX_C "Read error on media socket: %i (%s) -- closing call", LOG_PARAMS_C(c), i, strerror(i));

	call_destroy(c);
}




/* called with in_lock held */
void kernelize(struct packet_stream *stream) {
	struct mediaproxy_target_info mpt;
	struct call *call = stream->call;
	struct callmaster *cm = call->callmaster;
	struct packet_stream *sink = NULL;

	if (stream->kernelized)
		return;
	if (cm->conf.kernelfd < 0 || cm->conf.kernelid == -1)
		goto no_kernel;

	mylog(LOG_DEBUG, LOG_PREFIX_C "Kernelizing media stream with local port %u",
			LOG_PARAMS_C(call), stream->sfd->fd.localport);

	sink = stream->rtp_sink;
	if (!sink && stream->rtcp)
		sink = stream->rtcp_sink;
	if (!sink) {
		mylog(LOG_WARNING, LOG_PREFIX_C "Attempt to kernelize stream without sink",
				LOG_PARAMS_C(call));
		goto no_kernel;
	}

	ZERO(mpt);

	determine_handler(stream, sink);

	if (is_addr_unspecified(&sink->advertised_endpoint.ip46)
			|| !sink->advertised_endpoint.port)
		goto no_kernel;
	if (!stream->handler->in->kernel
			|| !stream->handler->out->kernel)
		goto no_kernel;

	mutex_lock(&sink->out_lock);

	mpt.target_port = stream->sfd->fd.localport;
	mpt.tos = cm->conf.tos;
	mpt.src_addr.port = sink->sfd->fd.localport;
	mpt.dst_addr.port = sink->endpoint.port;
	mpt.rtcp_mux = stream->media->rtcp_mux;

	if (IN6_IS_ADDR_V4MAPPED(&sink->endpoint.ip46)) {
		mpt.src_addr.family = AF_INET;
		mpt.src_addr.ipv4 = cm->conf.ipv4;
		mpt.dst_addr.family = AF_INET;
		mpt.dst_addr.ipv4 = sink->endpoint.ip46.s6_addr32[3];
	}
	else {
		mpt.src_addr.family = AF_INET6;
		memcpy(mpt.src_addr.ipv6, &cm->conf.ipv6, sizeof(mpt.src_addr.ipv6));
		mpt.dst_addr.family = AF_INET6;
		memcpy(mpt.dst_addr.ipv6, &sink->endpoint.ip46, sizeof(mpt.src_addr.ipv6));
	}

	stream->handler->in->kernel(&mpt.decrypt, stream);
	stream->handler->out->kernel(&mpt.encrypt, sink);

	mutex_unlock(&stream->out_lock);

	if (!mpt.encrypt.cipher || !mpt.encrypt.hmac)
		goto no_kernel;
	if (!mpt.decrypt.cipher || !mpt.decrypt.hmac)
		goto no_kernel;

	ZERO(stream->kernel_stats);

	kernel_add_stream(cm->conf.kernelfd, &mpt, 0);
	stream->kernelized = 1;

	return;
	
no_kernel:
	stream->kernelized = 1;
	stream->no_kernel_support = 1;
}




/* returns: 0 = not a muxed stream, 1 = muxed, RTP, 2 = muxed, RTCP */
static int rtcp_demux(str *s, struct call_media *media) {
	if (!media->rtcp_mux)
		return 0;
	return rtcp_demux_is_rtcp(s) ? 2 : 1;
}

static int call_avpf2avp_rtcp(str *s, struct packet_stream *stream) {
	return rtcp_avpf2avp(s);
}
static int call_avp2savp_rtp(str *s, struct packet_stream *stream) {
	return rtp_avp2savp(s, &stream->crypto);
}
static int call_avp2savp_rtcp(str *s, struct packet_stream *stream) {
	return rtcp_avp2savp(s, &stream->crypto);
}
static int call_savp2avp_rtp(str *s, struct packet_stream *stream) {
	return rtp_savp2avp(s, &stream->sfd->crypto);
}
static int call_savp2avp_rtcp(str *s, struct packet_stream *stream) {
	return rtcp_savp2avp(s, &stream->sfd->crypto);
}
static int call_savpf2avp_rtcp(str *s, struct packet_stream *stream) {
	int ret;
	ret = rtcp_savp2avp(s, &stream->sfd->crypto);
	if (ret < 0)
		return ret;
	return rtcp_avpf2avp(s);
}


static int __k_null(struct mediaproxy_srtp *s, struct packet_stream *stream) {
	*s = __mps_null;
	return 0;
}
static int __k_srtp_crypt(struct mediaproxy_srtp *s, struct crypto_context *c) {
	if (!c->signal.crypto_suite)
		return -1;

	*s = (struct mediaproxy_srtp) {
		.cipher		= c->signal.crypto_suite->kernel_cipher,
		.hmac		= c->signal.crypto_suite->kernel_hmac,
		.mki		= c->signal.mki,
		.mki_len	= c->signal.mki_len,
		.last_index	= c->oper.last_index,
		.auth_tag_len	= c->signal.crypto_suite->srtp_auth_tag,
	};
	memcpy(s->master_key, c->signal.master_key, c->signal.crypto_suite->master_key_len);
	memcpy(s->master_salt, c->signal.master_salt, c->signal.crypto_suite->master_salt_len);
	return 0;
}
static int __k_srtp_encrypt(struct mediaproxy_srtp *s, struct packet_stream *stream) {
	return __k_srtp_crypt(s, &stream->crypto);
}
static int __k_srtp_decrypt(struct mediaproxy_srtp *s, struct packet_stream *stream) {
	return __k_srtp_crypt(s, &stream->sfd->crypto);
}

/* must be called with call->master_lock held in R, and in->in_lock and out->out_lock held */
static void determine_handler(struct packet_stream *in, struct packet_stream *out) {
	const struct streamhandler **sh_pp, *sh;

	if (in->has_handler)
		return;

	if (in->media->protocol == PROTO_UNKNOWN)
		goto err;
	if (out->media->protocol == PROTO_UNKNOWN)
		goto err;

	sh_pp = __sh_matrix[in->media->protocol];
	if (!sh_pp)
		goto err;
	sh = sh_pp[out->media->protocol];
	if (!sh)
		goto err;
	in->handler = sh;

done:
	in->has_handler = 1;
	return;

err:
	mylog(LOG_WARNING, "Unknown transport protocol encountered");
	in->handler = &__sh_noop;
	goto done;
}

void callmaster_msg_mh_src(struct callmaster *cm, struct msghdr *mh) {
	struct cmsghdr *ch;
	struct in_pktinfo *pi;
	struct in6_pktinfo *pi6;
	struct sockaddr_in6 *sin6;

	sin6 = mh->msg_name;

	ch = CMSG_FIRSTHDR(mh);
	ZERO(*ch);

	if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
		ch->cmsg_len = CMSG_LEN(sizeof(*pi));
		ch->cmsg_level = IPPROTO_IP;
		ch->cmsg_type = IP_PKTINFO;

		pi = (void *) CMSG_DATA(ch);
		ZERO(*pi);
		pi->ipi_spec_dst.s_addr = cm->conf.ipv4;

		mh->msg_controllen = CMSG_SPACE(sizeof(*pi));
	}
	else {
		ch->cmsg_len = CMSG_LEN(sizeof(*pi6));
		ch->cmsg_level = IPPROTO_IPV6;
		ch->cmsg_type = IPV6_PKTINFO;

		pi6 = (void *) CMSG_DATA(ch);
		ZERO(*pi6);
		pi6->ipi6_addr = cm->conf.ipv6;

		mh->msg_controllen = CMSG_SPACE(sizeof(*pi6));
	}
}

/* called lock-free */
static int stream_packet(struct stream_fd *sfd, str *s, struct sockaddr_in6 *fsin) {
	struct packet_stream *stream = sfd->stream;
	struct packet_stream *sink = NULL;
	struct call_media *media;
	int ret = 0, update = 0, stun_ret = 0, handler_ret = 0, muxed_rtcp = 0, rtcp = 0;
	struct sockaddr_in6 sin6;
	struct msghdr mh;
	struct iovec iov;
	unsigned char buf[256];
	struct call *call;
	struct callmaster *cm;
	/*unsigned char cc;*/
	char addr[64];
	struct endpoint endpoint;
	rewrite_func rwf_in, rwf_out;

	assert(stream != NULL);
	media = stream->media;
	call = stream->call;
	cm = call->callmaster;
	smart_ntop_port(addr, fsin, sizeof(addr));

	rwlock_lock_r(&call->master_lock);
	mutex_lock(&stream->in_lock);

	/* XXX check send/receive flags */

	if (stream->stun && is_stun(s)) {
		stun_ret = stun(s, stream, fsin);
		if (!stun_ret)
			goto done;
		if (stun_ret == 1) /* use candidate */
			goto use_cand;
		else /* not an stun packet */
			stun_ret = 0;
	}

	sink = stream->rtp_sink;
	if (!sink && stream->rtcp) {
		sink = stream->rtcp_sink;
		rtcp = 1;
	}
	muxed_rtcp = rtcp_demux(s, media);
	if (muxed_rtcp == 2) {
		sink = stream->rtcp_sink;
		rtcp = 1;
	}

	if (!sink || !sink->sfd) {
		mylog(LOG_WARNING, LOG_PREFIX_C "RTP packet to port %u discarded from %s", 
			LOG_PARAMS_C(call), sfd->fd.localport, addr);
		stream->stats.errors++;
		mutex_lock(&cm->statspslock);
		cm->statsps.errors++;
		mutex_unlock(&cm->statspslock);
		goto done;
	}

	mutex_lock(&sink->out_lock);

	determine_handler(stream, sink);

	if (!rtcp) {
		rwf_in = stream->handler->in->rtp;
		rwf_out = stream->handler->out->rtp;
	}
	else {
		rwf_in = stream->handler->in->rtcp;
		rwf_out = stream->handler->out->rtcp;
	}

	/* return values are: 0 = forward packet, -1 = error/dont forward,
	 * 1 = forward and push update to redis */
	if (rwf_in)
		handler_ret = rwf_in(s, stream);
	if (handler_ret >= 0 && rwf_out)
		handler_ret += rwf_out(s, sink);

	if (handler_ret > 0)
		update = 1;

	mutex_unlock(&sink->out_lock);

use_cand:
	if (!stream->filled)
		goto forward;

	if (media->asymmetric)
		stream->confirmed = 1;

	if (stream->confirmed)
		goto kernel_check;

	if (!call->last_signal || poller_now <= call->last_signal + 3)
		goto peerinfo;

	mylog(LOG_DEBUG, LOG_PREFIX_C "Confirmed peer information for port %u - %s", 
		LOG_PARAMS_C(call), sfd->fd.localport, addr);

	stream->confirmed = 1;
	update = 1;

peerinfo:
	/*
	if (!stun_ret && !stream->codec && s->len >= 2) {
		cc = s->s[1];
		cc &= 0x7f;
		if (cc < G_N_ELEMENTS(rtp_codecs))
			stream->codec = rtp_codecs[cc] ? : "unknown";
		else
			stream->codec = "unknown";
	}
	*/

	mutex_lock(&stream->out_lock);
	endpoint = stream->endpoint;
	stream->endpoint.ip46 = fsin->sin6_addr;
	stream->endpoint.port = ntohs(fsin->sin6_port);
	if (memcmp(&endpoint, &stream->endpoint, sizeof(endpoint)))
		update = 1;
	mutex_unlock(&stream->out_lock);

kernel_check:
	if (stream->no_kernel_support)
		goto forward;

	if (stream->confirmed && sink && sink->confirmed && sink->filled)
		kernelize(stream);

forward:
	if (sink)
		mutex_lock(&sink->out_lock);

	if (!sink || is_addr_unspecified(&sink->advertised_endpoint.ip46)
			|| !sink->advertised_endpoint.port
			|| stun_ret || handler_ret < 0)
		goto drop;

	ZERO(mh);
	mh.msg_control = buf;
	mh.msg_controllen = sizeof(buf);

	ZERO(sin6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = sink->endpoint.ip46;
	sin6.sin6_port = htons(sink->endpoint.port);
	mh.msg_name = &sin6;
	mh.msg_namelen = sizeof(sin6);

	mutex_unlock(&sink->out_lock);

	callmaster_msg_mh_src(cm, &mh);

	ZERO(iov);
	iov.iov_base = s->s;
	iov.iov_len = s->len;

	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;

	ret = sendmsg(sink->sfd->fd.fd, &mh, 0);

	if (ret == -1) {
		stream->stats.errors++;
		mutex_lock(&cm->statspslock);
		cm->statsps.errors++;
		mutex_unlock(&cm->statspslock);
		goto out;
	}

	sink = NULL;

drop:
	if (sink)
		mutex_unlock(&sink->out_lock);
	ret = 0;
	stream->stats.packets++;
	stream->stats.bytes += s->len;
	stream->last_packet = poller_now;
	mutex_lock(&cm->statspslock);
	cm->statsps.packets++;
	cm->statsps.bytes += s->len;
	mutex_unlock(&cm->statspslock);

out:
	if (ret == 0 && update)
		ret = 1;

done:
	mutex_unlock(&stream->in_lock);
	rwlock_unlock_r(&call->master_lock);

	return ret;
}




static void stream_fd_readable(int fd, void *p, uintptr_t u) {
	struct stream_fd *sfd = p;
	char buf[RTP_BUFFER_SIZE];
	int ret;
	struct sockaddr_storage ss;
	struct sockaddr_in6 sin6;
	struct sockaddr_in *sin;
	unsigned int sinlen;
	void *sinp;
	int update = 0;
	struct call *ca;
	str s;

	if (sfd->fd.fd != fd)
		goto out;

	for (;;) {
		sinlen = sizeof(ss);
		ret = recvfrom(fd, buf + RTP_BUFFER_HEAD_ROOM, MAX_RTP_PACKET_SIZE,
				0, (struct sockaddr *) &ss, &sinlen);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			stream_fd_closed(fd, sfd, 0);
			return;
		}
		if (ret >= MAX_RTP_PACKET_SIZE)
			mylog(LOG_WARNING, "UDP packet possibly truncated");

		sinp = &ss;
		if (ss.ss_family == AF_INET) {
			sin = sinp;
			sinp = &sin6;
			ZERO(sin6);
			sin6.sin6_family = AF_INET6;
			sin6.sin6_port = sin->sin_port;
			in4_to_6(&sin6.sin6_addr, sin->sin_addr.s_addr);
		}

		str_init_len(&s, buf + RTP_BUFFER_HEAD_ROOM, ret);
		ret = stream_packet(sfd, &s, sinp);
		if (ret == -1) {
			mylog(LOG_WARNING, "Write error on RTP socket");
			call_destroy(sfd->call);
			return;
		}
		if (ret == 1)
			update = 1;
	}

out:
	ca = sfd->call ? : NULL;

	if (ca && update)
		redis_update(ca, sfd->call->callmaster->conf.redis);
}





static int info_parse_func(char **a, void **ret, void *p) {
	GHashTable *ih = p;

	g_hash_table_replace(ih, a[0], a[1]);

	return -1;
}


static void info_parse(const char *s, GHashTable *ih, struct callmaster *m) {
	pcre_multi_match(m->info_re, m->info_ree, s, 2, info_parse_func, ih, NULL);
}


static int streams_parse_func(char **a, void **ret, void *p) {
	struct stream_params *sp;
	u_int32_t ip;
	int *i;

	i = p;
	sp = g_slice_alloc0(sizeof(*sp));

	ip = inet_addr(a[0]);
	if (ip == -1)
		goto fail;

	in4_to_6(&sp->rtp_endpoint.ip46, ip);
	sp->rtp_endpoint.port = atoi(a[1]);
	sp->index = ++(*i);
	sp->consecutive_ports = 1;

	sp->rtcp_endpoint = sp->rtp_endpoint;
	sp->rtcp_endpoint.port++;

	if (!sp->rtp_endpoint.port && strcmp(a[1], "0"))
		goto fail;

	*ret = sp;
	return 0;

fail:
	mylog(LOG_WARNING, "Failed to parse a media stream: %s:%s", a[0], a[1]);
	g_slice_free1(sizeof(*sp), sp);
	return -1;
}


static void streams_parse(const char *s, struct callmaster *m, GQueue *q) {
	int i;
	i = 0;
	pcre_multi_match(m->streams_re, m->streams_ree, s, 3, streams_parse_func, &i, q);
}

static void streams_free(GQueue *q) {
	struct stream_params *s;

	while ((s = g_queue_pop_head(q)))
		g_slice_free1(sizeof(*s), s);
}



/* called with callmaster->hashlock held */
static void call_timer_iterator(void *key, void *val, void *ptr) {
	struct call *c = val;
	struct iterator_helper *hlp = ptr;
	GList *it;
	struct callmaster *cm;
	unsigned int check;
	int good = 0;
	struct packet_stream *ps;

	rwlock_lock_r(&c->master_lock);

	if (!c->streams)
		goto drop;

	cm = c->callmaster;

	for (it = c->streams; it; it = it->next) {
		ps = it->data;
		mutex_lock(&ps->in_lock);

		if (!ps->sfd)
			goto next;
		if (hlp->ports[ps->sfd->fd.localport])
			abort();
		hlp->ports[ps->sfd->fd.localport] = ps;
		obj_hold(ps);

		if (good)
			goto next;

		check = cm->conf.timeout;
		/* XXX silenced stream timeout handling
		if (!sr->peer_advertised.port)
			check = cm->conf.silent_timeout;
		else if (is_addr_unspecified(&sr->peer_advertised.ip46))
			check = cm->conf.silent_timeout;
		*/

		if (poller_now - ps->last_packet < check)
			good = 1;

next:
		mutex_unlock(&ps->in_lock);
	}

	if (good)
		goto out;

	mylog(LOG_INFO, LOG_PREFIX_C "Closing call branch due to timeout", 
		LOG_PARAMS_C(c));

drop:
	rwlock_unlock_r(&c->master_lock);
	hlp->del = g_slist_prepend(hlp->del, obj_get(c));
	return;

out:
	rwlock_unlock_r(&c->master_lock);
}

void xmlrpc_kill_calls(void *p) {
	struct xmlrpc_helper *xh = p;
	xmlrpc_env e;
	xmlrpc_client *c;
	xmlrpc_value *r;
	pid_t pid;
	sigset_t ss;
	int i = 0;
	int status;
	str *tag;

	while (xh->tags) {
		tag = xh->tags->data;

		mylog(LOG_INFO, "Forking child to close call with tag "STR_FORMAT" via XMLRPC", STR_FMT(tag));
		pid = fork();

		if (pid) {
retry:
			pid = waitpid(pid, &status, 0);
			if ((pid > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0) || i >= 3) {
				xh->tags = g_slist_delete_link(xh->tags, xh->tags);
				i = 0;
			}
			else {
				if (pid == -1 && errno == EINTR)
					goto retry;
				mylog(LOG_INFO, "XMLRPC child exited with status %i", status);
				i++;
			}
			continue;
		}

		/* child process */
		alarm(1); /* syslog functions contain a lock, which may be locked at
			     this point and can't be unlocked */
		rlim(RLIMIT_CORE, 0);
		sigemptyset(&ss);
		sigprocmask(SIG_SETMASK, &ss, NULL);
		closelog();

		for (i = 0; i < 100; i++)
			close(i);

		openlog("mediaproxy-ng/child", LOG_PID | LOG_NDELAY, LOG_DAEMON);
		mylog(LOG_INFO, "Initiating XMLRPC call for tag "STR_FORMAT"", STR_FMT(tag));

		alarm(5);

		xmlrpc_env_init(&e);
		xmlrpc_client_setup_global_const(&e);
		xmlrpc_client_create(&e, XMLRPC_CLIENT_NO_FLAGS, "ngcp-mediaproxy-ng", MEDIAPROXY_VERSION,
			NULL, 0, &c);
		if (e.fault_occurred)
			goto fault;

		r = NULL;
		xmlrpc_client_call2f(&e, c, xh->url, "di", &r, "(ssss)",
			"sbc", "postControlCmd", tag->s, "teardown");
		if (r)
			xmlrpc_DECREF(r);
		if (e.fault_occurred)
			goto fault;

		xmlrpc_client_destroy(c);
		xh->tags = g_slist_delete_link(xh->tags, xh->tags);
		xmlrpc_env_clean(&e);

		_exit(0);

fault:
		mylog(LOG_WARNING, "XMLRPC fault occurred: %s", e.fault_string);
		_exit(1);
	}

	g_string_chunk_free(xh->c);
	g_slice_free1(sizeof(*xh), xh);
}

void kill_calls_timer(GSList *list, struct callmaster *m) {
	struct call *ca;
	GList *csl;
	struct call_monologue *cm;
	const char *url;
	struct xmlrpc_helper *xh = NULL;

	if (!list)
		return; /* shouldn't happen */

	ca = list->data;
	m = ca->callmaster; /* same callmaster for all of them */
	url = m->conf.b2b_url;
	if (url) {
		xh = g_slice_alloc(sizeof(*xh));
		xh->c = g_string_chunk_new(64);
		xh->url = g_string_chunk_insert(xh->c, url);
		xh->tags = NULL;
	}

	while (list) {
		ca = list->data;
		if (!url)
			goto destroy;

		rwlock_lock_r(&ca->master_lock);

		for (csl = ca->monologues; csl; csl = csl->next) {
			cm = csl->data;
			if (!cm->tag.s || !cm->tag.len)
				goto next;
			xh->tags = g_slist_prepend(xh->tags, str_chunk_insert(xh->c, &cm->tag));
next:
			;
		}

		rwlock_unlock_r(&ca->master_lock);

destroy:
		call_destroy(ca);
		obj_put(ca);
		list = g_slist_delete_link(list, list);
	}

	if (xh)
		thread_create_detach(xmlrpc_kill_calls, xh);
}


#define DS(x) do {							\
		mutex_lock(&ps->in_lock);				\
		if (ke->stats.x < ps->kernel_stats.x)			\
			d = 0;						\
		else							\
			d = ke->stats.x - ps->kernel_stats.x;		\
		ps->stats.x += d;					\
		mutex_unlock(&ps->in_lock);				\
		mutex_lock(&m->statspslock);				\
		m->statsps.x += d;					\
		mutex_unlock(&m->statspslock);				\
	} while (0)
static void callmaster_timer(void *ptr) {
	struct callmaster *m = ptr;
	struct iterator_helper hlp;
	GList *i;
	struct mediaproxy_list_entry *ke;
	struct packet_stream *ps, *sink;
	u_int64_t d;
	struct stats tmpstats;
	int j, update;

	ZERO(hlp);

	rwlock_lock_r(&m->hashlock);
	g_hash_table_foreach(m->callhash, call_timer_iterator, &hlp);
	rwlock_unlock_r(&m->hashlock);

	mutex_lock(&m->statspslock);
	memcpy(&tmpstats, &m->statsps, sizeof(tmpstats));
	ZERO(m->statsps);
	mutex_unlock(&m->statspslock);
	mutex_lock(&m->statslock);
	memcpy(&m->stats, &tmpstats, sizeof(m->stats));
	mutex_unlock(&m->statslock);

	i = (m->conf.kernelid != -1) ? kernel_list(m->conf.kernelid) : NULL;
	while (i) {
		ke = i->data;

		ps = hlp.ports[ke->target.target_port];
		if (!ps)
			goto next;

		rwlock_lock_r(&ps->call->master_lock);

		DS(packets);
		DS(bytes);
		DS(errors);

		mutex_lock(&ps->in_lock);

		if (ke->stats.packets != ps->kernel_stats.packets)
			ps->last_packet = poller_now;

		ps->kernel_stats.packets = ke->stats.packets;
		ps->kernel_stats.bytes = ke->stats.bytes;
		ps->kernel_stats.errors = ke->stats.errors;

		update = 0;

		/* XXX common piece of code */
		sink = ps->rtp_sink;
		if (!sink)
			sink = ps->rtcp_sink;

		if (sink)
			mutex_lock(&sink->out_lock);

		if (sink && sink->crypto.signal.crypto_suite
				&& ke->target.encrypt.last_index - sink->crypto.oper.last_index > 0x4000) {
			sink->crypto.oper.last_index = ke->target.encrypt.last_index;
			update = 1;
		}
		if (ps->sfd->crypto.signal.crypto_suite
				&& ke->target.decrypt.last_index - ps->sfd->crypto.oper.last_index > 0x4000) {
			ps->sfd->crypto.oper.last_index = ke->target.decrypt.last_index;
			update = 1;
		}

		if (sink)
			mutex_unlock(&sink->out_lock);
		mutex_unlock(&ps->in_lock);
		rwlock_unlock_r(&ps->call->master_lock);

		if (update)
			redis_update(ps->call, m->conf.redis);

next:
		hlp.ports[ke->target.target_port] = NULL;
		g_slice_free1(sizeof(*ke), ke);
		i = g_list_delete_link(i, i);
	}

	for (j = 0; j < (sizeof(hlp.ports) / sizeof(*hlp.ports)); j++)
		if (hlp.ports[j])
			obj_put(hlp.ports[j]);

	if (!hlp.del)
		return;

	kill_calls_timer(hlp.del, m);
}
#undef DS


struct callmaster *callmaster_new(struct poller *p) {
	struct callmaster *c;
	const char *errptr;
	int erroff;

	c = obj_alloc0("callmaster", sizeof(*c), NULL);

	c->callhash = g_hash_table_new(str_hash, str_equal);
	if (!c->callhash)
		goto fail;
	c->poller = p;
	rwlock_init(&c->hashlock);

	c->info_re = pcre_compile("^([^:,]+)(?::(.*?))?(?:$|,)", PCRE_DOLLAR_ENDONLY | PCRE_DOTALL, &errptr, &erroff, NULL);
	if (!c->info_re)
		goto fail;
	c->info_ree = pcre_study(c->info_re, 0, &errptr);

	c->streams_re = pcre_compile("^([\\d.]+):(\\d+)(?::(.*?))?(?:$|,)", PCRE_DOLLAR_ENDONLY | PCRE_DOTALL, &errptr, &erroff, NULL);
	if (!c->streams_re)
		goto fail;
	c->streams_ree = pcre_study(c->streams_re, 0, &errptr);

	poller_add_timer(p, callmaster_timer, &c->obj);

	obj_put(c);
	return c;

fail:
	obj_put(c);
	return NULL;
}



static int get_port6(struct udp_fd *r, u_int16_t p, struct callmaster *m) {
	int fd;
	struct sockaddr_in6 sin;
	int tos;

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	nonblock(fd);
	reuseaddr(fd);
	tos = m->conf.tos;
#ifdef IPV6_TCLASS
	if (tos)
		setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos));
#else
#warning "Will not set IPv6 traffic class"
#endif
	ipv6only(fd, 0);

	ZERO(sin);
	sin.sin6_family = AF_INET6;
	sin.sin6_port = htons(p);
	if (bind(fd, (struct sockaddr *) &sin, sizeof(sin)))
		goto fail;

	r->fd = fd;

	return 0;

fail:
	close(fd);
	return -1;
}

static int get_port(struct udp_fd *r, u_int16_t p, struct callmaster *m) {
	int ret;

	assert(r->fd == -1);

	mutex_lock(&m->portlock);
	if (bit_array_isset(m->ports_used, p)) {
		mutex_unlock(&m->portlock);
		return -1;
	}
	bit_array_set(m->ports_used, p);
	mutex_unlock(&m->portlock);

	ret = get_port6(r, p, m);

	if (ret) {
		mutex_lock(&m->portlock);
		bit_array_clear(m->ports_used, p);
		mutex_unlock(&m->portlock);
		return ret;
	}

	r->localport = p;

	return 0;
}

static void release_port(struct udp_fd *r, struct callmaster *m) {
	if (r->fd == -1 || !r->localport)
		return;
	mutex_lock(&m->portlock);
	bit_array_clear(m->ports_used, r->localport);
	mutex_unlock(&m->portlock);
	close(r->fd);
	r->fd = -1;
	r->localport = 0;
}

static int __get_consecutive_ports(struct udp_fd *array, int array_len, int wanted_start_port, struct call *c) {
	int i, j, cycle = 0;
	struct udp_fd *it;
	u_int16_t port;
	struct callmaster *m = c->callmaster;

	memset(array, -1, sizeof(*array) * array_len);

	if (wanted_start_port > 0)
		port = wanted_start_port;
	else {
		mutex_lock(&m->portlock);
		port = m->lastport;
		mutex_unlock(&m->portlock);
	}

	while (1) {
		if (!wanted_start_port) {
			if (port < m->conf.port_min)
				port = m->conf.port_min;
			if ((port & 1))
				port++;
		}

		for (i = 0; i < array_len; i++) {
			it = &array[i];

			if (!wanted_start_port && port > m->conf.port_max) {
				port = 0;
				cycle++;
				goto release_restart;
			}

			if (get_port(it, port++, m))
				goto release_restart;
		}
		break;

release_restart:
		for (j = 0; j < i; j++)
			release_port(&array[j], m);

		if (cycle >= 2 || wanted_start_port > 0)
			goto fail;
	}

	/* success */
	mutex_lock(&m->portlock);
	m->lastport = port;
	mutex_unlock(&m->portlock);

	mylog(LOG_DEBUG, LOG_PREFIX_CI "Opened ports %u..%u for media relay", 
		LOG_PARAMS_CI(c), array[0].localport, array[array_len - 1].localport);
	return 0;

fail:
	mylog(LOG_ERR, LOG_PREFIX_CI "Failed to get %u consecutive UDP ports for relay",
			LOG_PARAMS_CI(c), array_len);
	return -1;
}

static struct call_media *__get_media(struct call_monologue *ml, GList **it, const struct stream_params *sp) {
	struct call_media *med;

	/* iterator points to last seen element, or NULL if uninitialized */
	if (!*it)
		*it = ml->medias.head;
	else
		*it = (*it)->next;

	/* possible incremental update, hunt for correct media struct */
	while (*it) {
		med = (*it)->data;
		/* XXX compare media type too? */
		if (med->index == sp->index) {
			DBG("found existing call_media for stream #%u", sp->index);
			return med;
		}
		*it = (*it)->next;
	}

	DBG("allocating new call_media for stream #%u", sp->index);
	med = g_slice_alloc0(sizeof(*med));
	med->monologue = ml;
	med->call = ml->call;
	med->index = sp->index;
	call_str_cpy(ml->call, &med->type, &sp->type);

	g_queue_push_tail(&ml->medias, med);
	*it = ml->medias.tail;

	return med;
}

static void stream_fd_free(void *p) {
	struct stream_fd *f = p;
	struct callmaster *m = f->call->callmaster;

	release_port(&f->fd, m);
	crypto_cleanup(&f->crypto);

	obj_put(f->call);
}

static struct endpoint_map *__get_endpoint_map(struct call_media *media, unsigned int num_ports,
		struct endpoint *ep)
{
	GList *l;
	struct endpoint_map *em;
	struct udp_fd fd_arr[16];
	unsigned int i;
	struct stream_fd *sfd;
	struct call *call = media->call;
	struct poller_item pi;
	struct poller *po = call->callmaster->poller;

	for (l = media->endpoint_maps; l; l = l->next) {
		em = l->data;
		if (em->wildcard && em->sfds.length >= num_ports) {
			if (ep)
				em->endpoint = *ep;
			return em;
		}
		if (!ep) /* creating wildcard map */
			break;
		if (memcmp(&em->endpoint, ep, sizeof(*ep)))
			continue;
		if (em->sfds.length >= num_ports)
			return em;
		/* endpoint matches, but not enough ports. flush existing ports
		 * and allocate a new set. */
		g_queue_clear(&em->sfds);
		goto alloc;
	}

	em = g_slice_alloc0(sizeof(*em));
	if (ep)
		em->endpoint = *ep;
	else
		em->wildcard = 1;
	g_queue_init(&em->sfds);
	media->endpoint_maps = g_list_prepend(media->endpoint_maps, em);

alloc:
	if (num_ports > G_N_ELEMENTS(fd_arr))
		return NULL;
	if (__get_consecutive_ports(fd_arr, num_ports, 0, media->call))
		return NULL;

	for (i = 0; i < num_ports; i++) {
		sfd = obj_alloc0("stream_fd", sizeof(*sfd), stream_fd_free);
		sfd->fd = fd_arr[i];
		sfd->call = obj_get(call);
		g_queue_push_tail(&em->sfds, sfd);
		call->stream_fds = g_list_prepend(call->stream_fds, obj_get(sfd));

		ZERO(pi);
		pi.fd = sfd->fd.fd;
		pi.obj = &sfd->obj;
		pi.readable = stream_fd_readable;
		pi.closed = stream_fd_closed;

		poller_add_item(po, &pi);
	}

	return em;
}

static void __assign_stream_fds(struct call_media *media, GList *sfds) {
	GList *l;
	struct packet_stream *ps;

	for (l = media->streams.head; l; l = l->next) {
		assert(sfds != NULL);
		ps = l->data;
		ps->sfd = sfds->data;
		sfds = sfds->next;
	}
}

static int __wildcard_endpoint_map(struct call_media *media, unsigned int num_ports) {
	struct endpoint_map *em;

	em = __get_endpoint_map(media, num_ports, NULL);
	if (!em)
		return -1;

	__assign_stream_fds(media, em->sfds.head);

	return 0;
}

static int __num_media_streams(struct call_media *media, unsigned int num_ports) {
	struct packet_stream *stream;
	struct call *call = media->call;
	int ret = 0;

	while (media->streams.length < num_ports) {
		DBG("allocating new packet_stream");
		stream = g_slice_alloc0(sizeof(*stream));
		mutex_init(&stream->in_lock);
		mutex_init(&stream->out_lock);
		stream->call = call;
		stream->media = media;
		stream->last_packet = poller_now;
		g_queue_push_tail(&media->streams, stream);
		call->streams = g_list_prepend(call->streams, stream);
		ret++;
	}

	g_queue_truncate(&media->streams, num_ports);

	return ret;
}

static void __init_streams(struct call_media *A, struct call_media *B, struct stream_params *sp) {
	GList *la, *lb;
	struct packet_stream *a, *b;
	unsigned int port_off = 0;

	la = A->streams.head;
	lb = B->streams.head;

	while (la) {
		assert(lb != NULL);
		a = la->data;
		b = lb->data;

		/* RTP */
		a->rtp_sink = b;

		if (sp) {
			a->endpoint = sp->rtp_endpoint;
			a->endpoint.port += port_off;
			a->advertised_endpoint = a->endpoint;
			a->filled = 1;
			a->sfd->crypto.signal = sp->crypto.signal;
		}

		/* RTCP */
		if (!B->rtcp_mux) {
			lb = lb->next;
			assert(lb != NULL);
			b = lb->data;
		}

		if (!A->rtcp_mux) {
			a->rtcp_sink = NULL;
			a->rtcp = 0;
			a->has_rtcp_in_next = 1;
		}
		else {
			a->rtcp_sink = b;
			a->rtcp = 1;
			a->implicit_rtcp = 0;
		}

		/* if muxing, this is the fallback RTCP port */
		la = la->next;
		assert(la != NULL);
		a = la->data;

		a->rtp_sink = NULL;
		a->rtcp_sink = b;
		a->rtcp = 1;

		if (sp) {
			a->endpoint = sp->rtcp_endpoint;
			if (!a->endpoint.port) {
				a->endpoint = sp->rtp_endpoint;
				a->endpoint.port++;
				a->implicit_rtcp = 1;
			}
			else
				a->implicit_rtcp = 0;
			a->endpoint.port += port_off;
			a->filled = 1;
			a->sfd->crypto.signal = sp->crypto.signal;
		}

		la = la->next;
		lb = lb->next;

		port_off += 2;
	}
}

/* called with call->master_lock held in W */
static int monologue_offer_answer(struct call_monologue *monologue, GQueue *streams) {
	struct stream_params *sp;
	GList *media_iter, *ml_media, *other_ml_media;
	struct call_media *media, *other_media;
	unsigned int num_ports;
	struct call_monologue *other_ml = monologue->active_dialogue;
	struct endpoint_map *em;

	monologue->call->last_signal = poller_now;

	/* we must have a complete dialogue, even though the to-tag (other_ml->tag)
	 * may not be known yet */
	if (!other_ml)
		return -1;

	ml_media = other_ml_media = NULL;

	for (media_iter = streams->head; media_iter; media_iter = media_iter->next) {
		sp = media_iter->data;
		DBG("processing media stream #%u", sp->index);

		/* first, check for existance of call_media struct on both sides of
		 * the dialogue */
		media = __get_media(monologue, &ml_media, sp);
		other_media = __get_media(other_ml, &other_ml_media, sp);
		/* THIS side corresponds to what's being sent to the recipient of the
		 * offer/answer. The OTHER side corresponds to what WILL BE sent to the
		 * offerer or WAS sent to the answerer. */

		/* deduct protocol from stream parameters received */
		if (other_media->protocol == PROTO_UNKNOWN) {
			other_media->protocol = sp->protocol;
			if (other_media->protocol == PROTO_UNKNOWN)
				other_media->protocol = PROTO_RTP_AVP;
		}
		if (media->protocol == PROTO_UNKNOWN)
			media->protocol = other_media->protocol;

		other_media->rtcp_mux = sp->rtcp_mux;

		/* deduct address family from stream parameters received */
		if (!other_media->desired_family) {
			other_media->desired_family = AF_INET;
			if (!IN6_IS_ADDR_V4MAPPED(&sp->rtp_endpoint.ip46))
				other_media->desired_family = AF_INET6;
		}
		/* for outgoing SDP, use "direction" or default to IPv4 (?) */
		if (!media->desired_family) {
			media->desired_family = AF_INET;
			if (sp->direction[1] == DIR_EXTERNAL)
				media->desired_family = AF_INET6;
		}


		/* determine number of consecutive ports needed locally.
		 * XXX only do *=2 for RTP streams? */
		num_ports = sp->consecutive_ports;
		num_ports *= 2;

		/* get that many ports for each side, and one packet stream for each port, then
		 * assign the ports to the streams */
		em = __get_endpoint_map(media, num_ports, &sp->rtp_endpoint);
		if (!em)
			goto error;

		__num_media_streams(media, num_ports);
		__assign_stream_fds(media, em->sfds.head);

		if (__num_media_streams(other_media, num_ports)) {
			/* new streams created on OTHER side. normally only happens in
			 * initial offer. create a wildcard endpoint_map to be filled in
			 * when the answer comes. */
			if (__wildcard_endpoint_map(other_media, num_ports))
				goto error;
		}

		__init_streams(media, other_media, NULL);
		__init_streams(other_media, media, sp);
	}

	return 0;

error:
	mylog(LOG_ERR, "Error allocating media ports");
	return -1;
}

/* must be called with in_lock held or call->master_lock held in W */
static void unkernelize(struct packet_stream *p) {
	if (!p->kernelized)
		return;
	if (p->no_kernel_support)
		return;

	kernel_del_stream(p->call->callmaster->conf.kernelfd, p->sfd->fd.localport);

	p->kernelized = 0;
}

/* called lock-free, but must hold a reference to the call */
static void call_destroy(struct call *c) {
	struct callmaster *m = c->callmaster;
	struct packet_stream *ps;
	struct stream_fd *sfd;
	struct poller *p = m->poller;
	GList *l;
	int ret;

	rwlock_lock_w(&m->hashlock);
	ret = g_hash_table_remove(m->callhash, &c->callid);
	rwlock_unlock_w(&m->hashlock);

	if (!ret)
		return;

	obj_put(c);

	redis_delete(c, m->conf.redis);

	rwlock_lock_w(&c->master_lock);
	/* at this point, no more packet streams can be added */

	mylog(LOG_INFO, LOG_PREFIX_C "Final packet stats:", LOG_PARAMS_C(c));
	for (l = c->streams; l; l = l->next) {
		ps = l->data;

		/* XXX
		mylog(LOG_INFO, LOG_PREFIX_C
			"--- "
			"side A: "
			"RTP[%u] %lu p, %lu b, %lu e; "
			"RTCP[%u] %lu p, %lu b, %lu e; "
			"side B: "
			"RTP[%u] %lu p, %lu b, %lu e; "
			"RTCP[%u] %lu p, %lu b, %lu e",
			LOG_PARAMS_C(c),
			s->peers[0].rtps[0].fd.localport, s->peers[0].rtps[0].stats.packets,
			s->peers[0].rtps[0].stats.bytes, s->peers[0].rtps[0].stats.errors,
			s->peers[0].rtps[1].fd.localport, s->peers[0].rtps[1].stats.packets,
			s->peers[0].rtps[1].stats.bytes, s->peers[0].rtps[1].stats.errors,
			s->peers[1].rtps[0].fd.localport, s->peers[1].rtps[0].stats.packets,
			s->peers[1].rtps[0].stats.bytes, s->peers[1].rtps[0].stats.errors,
			s->peers[1].rtps[1].fd.localport, s->peers[1].rtps[1].stats.packets,
			s->peers[1].rtps[1].stats.bytes, s->peers[1].rtps[1].stats.errors);
		*/

		unkernelize(ps);
		ps->sfd = NULL;
		crypto_cleanup(&ps->crypto);

		ps->rtp_sink = NULL;
		ps->rtcp_sink = NULL;
	}

	while (c->stream_fds) {
		sfd = c->stream_fds->data;
		c->stream_fds = g_list_delete_link(c->stream_fds, c->stream_fds);
		poller_del_item(p, sfd->fd.fd);
		obj_put(sfd);
	}

	rwlock_unlock_w(&c->master_lock);
}



typedef int (*csa_func)(char *o, struct packet_stream *ps, enum stream_address_format format, int *len);

static int call_stream_address4(char *o, struct packet_stream *ps, enum stream_address_format format, int *len) {
	u_int32_t ip4;
	struct callmaster *m = ps->call->callmaster;
	int l = 0;

	if (format == SAF_NG) {
		strcpy(o + l, "IP4 ");
		l = 4;
	}

	ip4 = ps->advertised_endpoint.ip46.s6_addr32[3];
	if (!ip4) {
		strcpy(o + l, "0.0.0.0");
		l += 7;
	}
	else if (m->conf.adv_ipv4)
		l += sprintf(o + l, IPF, IPP(m->conf.adv_ipv4));
	else
		l += sprintf(o + l, IPF, IPP(m->conf.ipv4));

	*len = l;
	return AF_INET;
}

static int call_stream_address6(char *o, struct packet_stream *ps, enum stream_address_format format, int *len) {
	struct callmaster *m = ps->call->callmaster;
	int l = 0;

	if (format == SAF_NG) {
		strcpy(o + l, "IP6 ");
		l += 4;
	}

	if (is_addr_unspecified(&ps->advertised_endpoint.ip46)) {
		strcpy(o + l, "::");
		l += 2;
	}
	else {
		if (!is_addr_unspecified(&m->conf.adv_ipv6))
			inet_ntop(AF_INET6, &m->conf.adv_ipv6, o + l, 45); /* lies... */
		else
			inet_ntop(AF_INET6, &m->conf.ipv6, o + l, 45);
		l += strlen(o + l);
	}

	*len = l;
	return AF_INET6;
}

static csa_func __call_stream_address(struct packet_stream *ps, int variant) {
	struct callmaster *m;
	struct packet_stream *sink;
	struct call_media *sink_media;
	csa_func variants[2];

	assert(variant >= 0);
	assert(variant < G_N_ELEMENTS(variants));

	m = ps->call->callmaster;
	sink = ps->rtp_sink;
	if (!sink)
		sink = ps->rtcp_sink;
	sink_media = sink->media;

	variants[0] = call_stream_address4;
	variants[1] = call_stream_address6;

	if (is_addr_unspecified(&m->conf.ipv6)) {
		variants[1] = NULL;
		goto done;
	}
	if (sink_media->desired_family == AF_INET)
		goto done;
	if (sink_media->desired_family == 0 && IN6_IS_ADDR_V4MAPPED(&sink->endpoint.ip46))
		goto done;
	if (sink_media->desired_family == 0 && is_addr_unspecified(&sink->advertised_endpoint.ip46))
		goto done;

	variants[0] = call_stream_address6;
	variants[1] = call_stream_address4;
	goto done;

done:
	return variants[variant];
}

int call_stream_address(char *o, struct packet_stream *ps, enum stream_address_format format, int *len) {
	csa_func f;

	ps = ps->rtcp_sink ? : ps->rtp_sink;
	f = __call_stream_address(ps, 0);
	return f(o, ps, format, len);
}

int call_stream_address_alt(char *o, struct packet_stream *ps, enum stream_address_format format, int *len) {
	csa_func f;

	ps = ps->rtcp_sink ? : ps->rtp_sink;
	f = __call_stream_address(ps, 1);
	return f ? f(o, ps, format, len) : -1;
}

int callmaster_has_ipv6(struct callmaster *m) {
	return is_addr_unspecified(&m->conf.ipv6) ? 0 : 1;
}

static int call_stream_address_gstring(GString *o, struct packet_stream *ps, enum stream_address_format format) {
	int len, ret;
	char buf[64]; /* 64 bytes ought to be enough for anybody */

	ret = call_stream_address(buf, ps, format, &len);
	g_string_append_len(o, buf, len);
	return ret;
}



static str *streams_print(GQueue *s, int start, int end, const char *prefix, enum stream_address_format format) {
	GString *o;
	int i;
	GList *l;
	struct call_media *media;
	struct packet_stream *ps;
	int af;

	o = g_string_new_str();
	if (prefix)
		g_string_append_printf(o, "%s ", prefix);

	for (i = start; i < end; i++) {
		for (l = s->head; l; l = l->next) {
			media = l->data;
			if (media->index == i)
				goto found;
		}
		mylog(LOG_WARNING, "Requested media index %i not found", i);
		goto out;

found:
		if (!media->streams.head) {
			mylog(LOG_WARNING, "Media has no streams");
			goto out;
		}
		ps = media->streams.head->data;

		if (format == SAF_TCP)
			call_stream_address_gstring(o, ps, format);

		g_string_append_printf(o, (format == 1) ? "%u " : " %u", ps->sfd->fd.localport);

		if (format == SAF_UDP) {
			af = call_stream_address_gstring(o, ps, format);
			g_string_append_printf(o, " %c", (af == AF_INET) ? '4' : '6');
		}

	}

out:
	g_string_append(o, "\n");

	return g_string_free_str(o);
}

static void __call_free(void *p) {
	struct call *c = p;
	struct call_monologue *m;
	struct call_media *md;
	struct packet_stream *ps;
	struct endpoint_map *em;
	GList *it;

	call_buffer_free(&c->buffer);
	mutex_destroy(&c->buffer_lock);
	rwlock_destroy(&c->master_lock);

	while (c->monologues) {
		m = c->monologues->data;
		c->monologues = g_list_delete_link(c->monologues, c->monologues);

		g_hash_table_destroy(m->other_tags);

		for (it = m->medias.head; it; it = it->next) {
			md = it->data;
			g_queue_clear(&md->streams);
			while (md->endpoint_maps) {
				em = md->endpoint_maps->data;
				md->endpoint_maps = g_list_delete_link(md->endpoint_maps, md->endpoint_maps);
				g_queue_clear(&em->sfds);
				g_slice_free1(sizeof(*em), em);
			}
			g_slice_free1(sizeof(*md), md);
		}
		g_queue_clear(&m->medias);

		g_slice_free1(sizeof(*m), m);
	}

	g_hash_table_destroy(c->tags);

	while (c->streams) {
		ps = c->streams->data;
		c->streams = g_list_delete_link(c->streams, c->streams);
		g_slice_free1(sizeof(*ps), ps);
	}

	assert(c->stream_fds == NULL);
}

static struct call *call_create(const str *callid, struct callmaster *m) {
	struct call *c;

	mylog(LOG_NOTICE, LOG_PREFIX_C "Creating new call",
		STR_FMT(callid));	/* XXX will spam syslog on recovery from DB */
	c = obj_alloc0("call", sizeof(*c), __call_free);
	c->callmaster = m;
	mutex_init(&c->buffer_lock);
	call_buffer_init(&c->buffer);
	rwlock_init(&c->master_lock);
	c->tags = g_hash_table_new(str_hash, str_equal);
	call_str_cpy(c, &c->callid, callid);
	c->created = poller_now;
	return c;
}

/* returns call with master_lock held in W */
struct call *call_get_or_create(const str *callid, struct callmaster *m) {
	struct call *c;

restart:
	rwlock_lock_r(&m->hashlock);
	c = g_hash_table_lookup(m->callhash, callid);
	if (!c) {
		rwlock_unlock_r(&m->hashlock);
		/* completely new call-id, create call */
		c = call_create(callid, m);
		rwlock_lock_w(&m->hashlock);
		if (g_hash_table_lookup(m->callhash, callid)) {
			/* preempted */
			rwlock_unlock_w(&m->hashlock);
			obj_put(c);
			goto restart;
		}
		g_hash_table_insert(m->callhash, &c->callid, obj_get(c));
		rwlock_lock_w(&c->master_lock);
		rwlock_unlock_w(&m->hashlock);
	}
	else {
		obj_hold(c);
		rwlock_lock_w(&c->master_lock);
		rwlock_unlock_r(&m->hashlock);
	}

	return c;
}

/* returns call with master_lock held in W, or NULL if not found */
static struct call *call_get(const str *callid, struct callmaster *m) {
	struct call *ret;

	rwlock_lock_r(&m->hashlock);
	ret = g_hash_table_lookup(m->callhash, callid);
	if (!ret) {
		rwlock_unlock_r(&m->hashlock);
		return NULL;
	}

	rwlock_lock_w(&ret->master_lock);
	obj_hold(ret);
	rwlock_unlock_r(&m->hashlock);

	return ret;
}

/* returns call with master_lock held in W, or possibly NULL iff opmode == OP_ANSWER */
static struct call *call_get_opmode(const str *callid, struct callmaster *m, enum call_opmode opmode) {
	if (opmode == OP_OFFER)
		return call_get_or_create(callid, m);
	return call_get(callid, m);
}

/* must be called with call->master_lock held in W */
static struct call_monologue *__monologue_create(struct call *call) {
	struct call_monologue *ret;

	DBG("creating new monologue");
	ret = g_slice_alloc0(sizeof(*ret));

	ret->call = call;
	ret->created = poller_now;
	ret->other_tags = g_hash_table_new(str_hash, str_equal);
	g_queue_init(&ret->medias);

	call->monologues = g_list_prepend(call->monologues, ret);

	return ret;
}

/* must be called with call->master_lock held in W */
static void __monologue_tag(struct call_monologue *ml, const str *tag) {
	struct call *call = ml->call;

	DBG("tagging monologue with '"STR_FORMAT"'", STR_FMT(tag));
	call_str_cpy(call, &ml->tag, tag);
	g_hash_table_insert(call->tags, &ml->tag, ml);
}

/* must be called with call->master_lock held in W */
static void __monologue_unkernelize(struct call_monologue *monologue) {
	GList *l, *m;
	struct call_media *media;
	struct packet_stream *stream;

	if (!monologue)
		return;

	for (l = monologue->medias.head; l; l = l->next) {
		media = l->data;

		for (m = media->streams.head; m; m = m->next) {
			stream = m->data;
			unkernelize(stream);
			stream->confirmed = 0;
			stream->has_handler = 0;
		}
	}
}

/* must be called with call->master_lock held in W */
static void __monologue_destroy(struct call_monologue *monologue) {
	struct call_monologue *dialogue;
	GList *l;

	l = g_hash_table_get_values(monologue->other_tags);

	while (l) {
		dialogue = l->data;
		l = g_list_delete_link(l, l);
		g_hash_table_remove(dialogue->other_tags, &monologue->tag);
	}
}

/* must be called with call->master_lock held in W */
static struct call_monologue *call_get_monologue(struct call *call, const str *fromtag) {
	struct call_monologue *ret;

	DBG("getting monologue for tag '"STR_FORMAT"' in call '"STR_FORMAT"'",
			STR_FMT(fromtag), STR_FMT(&call->callid));
	ret = g_hash_table_lookup(call->tags, fromtag);
	if (ret) {
		DBG("found existing monologue");
		__monologue_unkernelize(ret);
		__monologue_unkernelize(ret->active_dialogue);
		return ret;
	}

	ret = __monologue_create(call);
	__monologue_tag(ret, fromtag);
	/* we need both sides of the dialogue even in the initial offer, so create
	 * another monologue without to-tag (to be filled in later) */
	ret->active_dialogue = __monologue_create(call);

	return ret;
}

/* must be called with call->master_lock held in W */
static struct call_monologue *call_get_dialogue(struct call *call, const str *fromtag, const str *totag) {
	struct call_monologue *ft, *ret;

	DBG("getting dialogue for tags '"STR_FORMAT"'<>'"STR_FORMAT"' in call '"STR_FORMAT"'",
			STR_FMT(fromtag), STR_FMT(totag), STR_FMT(&call->callid));
	/* if the to-tag is known already, return that */
	ret = g_hash_table_lookup(call->tags, totag);
	if (ret) {
		DBG("found existing dialogue");
		__monologue_unkernelize(ret);
		__monologue_unkernelize(ret->active_dialogue);
		return ret;
	}

	/* otherwise, at least the from-tag has to be known. it's an error if it isn't */
	ft = g_hash_table_lookup(call->tags, fromtag);
	if (!ft)
		return NULL;

	__monologue_unkernelize(ft);

	/* check for a half-complete dialogue and fill in the missing half if possible */
	ret = ft->active_dialogue;
	__monologue_unkernelize(ret);

	if (!ret->tag.s)
		goto tag;

	/* this is an additional dialogue created from a single from-tag */
	ret = __monologue_create(call);

tag:
	__monologue_tag(ret, totag);
	g_hash_table_insert(ret->other_tags, &ft->tag, ft);
	g_hash_table_insert(ft->other_tags, &ret->tag, ret);
	ret->active_dialogue = ft;
	ft->active_dialogue = ret;
	/* XXX possible asymmetric dialogue? */

	return ret;
}

static struct call_monologue *call_get_mono_dialogue(struct call *call, const str *fromtag, const str *totag) {
	if (!totag || !totag->s) /* offer, not answer */
		return call_get_monologue(call, fromtag);
	return call_get_dialogue(call, fromtag, totag);
}

static int addr_parse_udp(struct stream_params *sp, char **out) {
	u_int32_t ip4;
	const char *cp;
	char c;
	int i;

	ZERO(*sp);
	if (out[RE_UDP_UL_ADDR4] && *out[RE_UDP_UL_ADDR4]) {
		ip4 = inet_addr(out[RE_UDP_UL_ADDR4]);
		if (ip4 == -1)
			goto fail;
		in4_to_6(&sp->rtp_endpoint.ip46, ip4);
	}
	else if (out[RE_UDP_UL_ADDR6] && *out[RE_UDP_UL_ADDR6]) {
		if (inet_pton(AF_INET6, out[RE_UDP_UL_ADDR6], &sp->rtp_endpoint.ip46) != 1)
			goto fail;
	}
	else
		goto fail;

	sp->rtp_endpoint.port = atoi(out[RE_UDP_UL_PORT]);
	if (!sp->rtp_endpoint.port && strcmp(out[RE_UDP_UL_PORT], "0"))
		goto fail;

	if (out[RE_UDP_UL_FLAGS] && *out[RE_UDP_UL_FLAGS]) {
		i = 0;
		for (cp =out[RE_UDP_UL_FLAGS]; *cp && i < 2; cp++) {
			c = chrtoupper(*cp);
			if (c == 'E')
				sp->direction[i++] = DIR_EXTERNAL;
			else if (c == 'I')
				sp->direction[i++] = DIR_INTERNAL;
		}
	}

	if (out[RE_UDP_UL_NUM] && *out[RE_UDP_UL_NUM])
		sp->index = atoi(out[RE_UDP_UL_NUM]);
	if (!sp->index)
		sp->index = 1;
	sp->consecutive_ports = 1;

	return 0;
fail:
	return -1;
}

static str *call_update_lookup_udp(char **out, struct callmaster *m, enum call_opmode opmode) {
	struct call *c;
	struct call_monologue *monologue;
	GQueue q = G_QUEUE_INIT;
	struct stream_params sp;
	str *ret, callid, viabranch, fromtag, totag = STR_NULL;

	str_init(&callid, out[RE_UDP_UL_CALLID]);
	str_init(&viabranch, out[RE_UDP_UL_VIABRANCH]);
	str_init(&fromtag, out[RE_UDP_UL_FROMTAG]);
	if (opmode == OP_ANSWER)
		str_init(&totag, out[RE_UDP_UL_TOTAG]);

	c = call_get_opmode(&callid, m, opmode);
	if (!c) {
		mylog(LOG_WARNING, LOG_PREFIX_CI "Got UDP LOOKUP for unknown call-id",
			STR_FMT(&callid), STR_FMT(&viabranch));
		return str_sprintf("%s 0 " IPF "\n", out[RE_UDP_COOKIE], IPP(m->conf.ipv4));
	}
	//log_info = &viabranch;
	monologue = call_get_mono_dialogue(c, &fromtag, &totag);

	if (addr_parse_udp(&sp, out))
		goto fail;

	g_queue_push_tail(&q, &sp);
	/* XXX return value */
	monologue_offer_answer(monologue, &q);
	g_queue_clear(&q);

	ret = streams_print(&monologue->medias, sp.index, sp.index, out[RE_UDP_COOKIE], SAF_UDP);
	rwlock_unlock_w(&c->master_lock);

	redis_update(c, m->conf.redis);

	mylog(LOG_INFO, LOG_PREFIX_CI "Returning to SIP proxy: "STR_FORMAT"", LOG_PARAMS_CI(c), STR_FMT(ret));
	goto out;

fail:
	rwlock_unlock_w(&c->master_lock);
	mylog(LOG_WARNING, "Failed to parse a media stream: %s/%s:%s", out[RE_UDP_UL_ADDR4], out[RE_UDP_UL_ADDR6], out[RE_UDP_UL_PORT]);
	ret = str_sprintf("%s E8\n", out[RE_UDP_COOKIE]);
out:
	log_info = NULL;
	obj_put(c);
	return ret;
}

str *call_update_udp(char **out, struct callmaster *m) {
	return call_update_lookup_udp(out, m, OP_OFFER);
}
str *call_lookup_udp(char **out, struct callmaster *m) {
	return call_update_lookup_udp(out, m, OP_ANSWER);
}

static str *call_request_lookup_tcp(char **out, struct callmaster *m, enum call_opmode opmode) {
	struct call *c;
	struct call_monologue *monologue;
	GQueue s = G_QUEUE_INIT;
	str *ret = NULL, callid, fromtag, totag = STR_NULL;
	GHashTable *infohash;

	str_init(&callid, out[RE_TCP_RL_CALLID]);
	infohash = g_hash_table_new(g_str_hash, g_str_equal);
	c = call_get_opmode(&callid, m, opmode);
	if (!c) {
		mylog(LOG_WARNING, LOG_PREFIX_C "Got LOOKUP for unknown call-id", STR_FMT(&callid));
		goto out;
	}

	info_parse(out[RE_TCP_RL_INFO], infohash, m);
	streams_parse(out[RE_TCP_RL_STREAMS], m, &s);
	str_init(&fromtag, g_hash_table_lookup(infohash, "fromtag"));
	if (!fromtag.s) {
		mylog(LOG_WARNING, LOG_PREFIX_C "No from-tag in message", LOG_PARAMS_C(c));
		goto out2;
	}
	if (opmode == OP_ANSWER) {
		str_init(&totag, g_hash_table_lookup(infohash, "totag"));
		if (!totag.s) {
			mylog(LOG_WARNING, LOG_PREFIX_C "No to-tag in message", LOG_PARAMS_C(c));
			goto out2;
		}
	}

	monologue = call_get_mono_dialogue(c, &fromtag, &totag);
	/* XXX return value */
	monologue_offer_answer(monologue, &s);

	ret = streams_print(&monologue->medias, 1, s.length, NULL, SAF_TCP);
	rwlock_unlock_w(&c->master_lock);

out2:
	streams_free(&s);

	redis_update(c, m->conf.redis);

	mylog(LOG_INFO, LOG_PREFIX_C "Returning to SIP proxy: "STR_FORMAT"", LOG_PARAMS_C(c), STR_FMT0(ret));
	obj_put(c);

out:
	g_hash_table_destroy(infohash);
	return ret;
}

str *call_request_tcp(char **out, struct callmaster *m) {
	return call_request_lookup_tcp(out, m, OP_OFFER);
}
str *call_lookup_tcp(char **out, struct callmaster *m) {
	return call_request_lookup_tcp(out, m, OP_ANSWER);
}

static int call_delete_branch(struct callmaster *m, const str *callid, const str *branch,
	const str *fromtag, const str *totag, bencode_item_t *output)
{
	struct call *c;
	struct call_monologue *ml;
	int ret;
	const str *match_tag;

	c = call_get(callid, m);
	if (!c) {
		mylog(LOG_INFO, LOG_PREFIX_C "Call-ID to delete not found", STR_FMT(callid));
		goto err;
	}

	//log_info = branch;

	if (!fromtag || !fromtag->s || !fromtag->len)
		goto del_all;

	match_tag = (totag && totag->s && totag->len) ? totag : fromtag;

	ml = g_hash_table_lookup(c->tags, match_tag);
	if (!ml) {
		mylog(LOG_INFO, LOG_PREFIX_C "Tag '"STR_FORMAT"' in delete message not found, ignoring",
				STR_FMT(match_tag), LOG_PARAMS_C(c));
		goto err;
	}

	if (output)
		ng_call_stats(c, fromtag, totag, output);

/*
	if (branch && branch->len) {
		if (!g_hash_table_remove(c->branches, branch)) {
			mylog(LOG_INFO, LOG_PREFIX_CI "Branch to delete doesn't exist", STR_FMT(&c->callid), STR_FMT(branch));
			goto err;
		}

		mylog(LOG_INFO, LOG_PREFIX_CI "Branch deleted", LOG_PARAMS_CI(c));
		if (g_hash_table_size(c->branches))
			goto success_unlock;
		else
			DBG("no branches left, deleting full call");
	}
*/

	__monologue_destroy(ml);
	goto success_unlock; /* XXX del full call */

del_all:
	rwlock_unlock_w(&c->master_lock);
	mylog(LOG_INFO, LOG_PREFIX_C "Deleting full call", LOG_PARAMS_C(c));
	call_destroy(c);
	goto success;

success_unlock:
	rwlock_unlock_w(&c->master_lock);
success:
	ret = 0;
	goto out;

err:
	if (c)
		rwlock_unlock_w(&c->master_lock);
	ret = -1;
	goto out;

out:
	log_info = NULL;
	if (c)
		obj_put(c);
	return ret;
}

str *call_delete_udp(char **out, struct callmaster *m) {
	str callid, branch, fromtag, totag;

	DBG("got delete for callid '%s' and viabranch '%s'", 
		out[RE_UDP_DQ_CALLID], out[RE_UDP_DQ_VIABRANCH]);

	str_init(&callid, out[RE_UDP_DQ_CALLID]);
	str_init(&branch, out[RE_UDP_DQ_VIABRANCH]);
	str_init(&fromtag, out[RE_UDP_DQ_FROMTAG]);
	str_init(&totag, out[RE_UDP_DQ_TOTAG]);

	if (call_delete_branch(m, &callid, &branch, &fromtag, &totag, NULL))
		return str_sprintf("%s E8\n", out[RE_UDP_COOKIE]);

	return str_sprintf("%s 0\n", out[RE_UDP_COOKIE]);
}

#define SSUM(x) \
	stats->totals[0].x += stream->stats.x;
/* call->master_lock must be held in W */
/* XXX possibly eliminate W lock, should work with R only */
static void stats_query(struct call *call, const str *fromtag, const str *totag, struct call_stats *stats,
	void (*cb)(struct packet_stream *, void *), void *arg)
{
	const str *match_tag;
	struct call_monologue *ml;
	struct call_media *media;
	GList *l, *m_l = NULL;
	struct packet_stream *stream;

	ZERO(*stats);

	match_tag = (totag && totag->s && totag->len) ? totag : fromtag;
	if (!match_tag)
		l = call->streams;
	else {
		ml = g_hash_table_lookup(call->tags, match_tag);
		if (!ml)
			goto out;
		m_l = ml->medias.head;

m_l_restart:
		if (!m_l)
			goto out;
		media = m_l->data;
		l = media->streams.head;
	}

	while (l) {
		stream = l->data;

		if (stream->last_packet > stats->newest)
			stats->newest = stream->last_packet;

		if (cb)
			cb(stream, arg);

		SSUM(packets);
		SSUM(bytes);
		SSUM(errors);

		/* XXX more meaningful stats */

		l = l->next;

		if (!l && m_l) {
			m_l = m_l->next;
			goto m_l_restart;
		}
	}

out:
	;
}

str *call_query_udp(char **out, struct callmaster *m) {
	struct call *c;
	str *ret, callid, fromtag, totag;
	struct call_stats stats;

	DBG("got query for callid '%s'", out[RE_UDP_DQ_CALLID]);

	str_init(&callid, out[RE_UDP_DQ_CALLID]);
	str_init(&fromtag, out[RE_UDP_DQ_FROMTAG]);
	str_init(&totag, out[RE_UDP_DQ_TOTAG]);

	c = call_get_opmode(&callid, m, OP_OTHER);
	if (!c) {
		mylog(LOG_INFO, LOG_PREFIX_C "Call-ID to query not found", STR_FMT(&callid));
		goto err;
	}

	stats_query(c, &fromtag, &totag, &stats, NULL, NULL);

	rwlock_unlock_w(&c->master_lock);

	ret = str_sprintf("%s %lld "UINT64F" "UINT64F" "UINT64F" "UINT64F"\n", out[RE_UDP_COOKIE],
		(long long int) m->conf.silent_timeout - (poller_now - stats.newest),
		stats.totals[0].packets, stats.totals[1].packets,
		stats.totals[2].packets, stats.totals[3].packets);
	goto out;

err:
	if (c)
		rwlock_unlock_w(&c->master_lock);
	ret = str_sprintf("%s E8\n", out[RE_UDP_COOKIE]);
	goto out;

out:
	if (c)
		obj_put(c);
	return ret;
}

void call_delete_tcp(char **out, struct callmaster *m) {
	str callid;

	str_init(&callid, out[RE_TCP_D_CALLID]);
	call_delete_branch(m, &callid, NULL, NULL, NULL, NULL);
}



static void call_status_iterator(struct call *c, struct control_stream *s) {
//	GList *l;
//	struct callstream *cs;
//	struct peer *p;
//	struct streamrelay *r1, *r2;
//	struct streamrelay *rx1, *rx2;
//	struct callmaster *m;
//	char addr1[64], addr2[64], addr3[64];

//	m = c->callmaster;
//	mutex_lock(&c->master_lock);

	control_stream_printf(s, "session "STR_FORMAT" - - - - %i\n",
		STR_FMT(&c->callid),
		(int) (poller_now - c->created));

	/* XXX restore function */

//	mutex_unlock(&c->master_lock);
}

static void callmaster_get_all_calls_interator(void *key, void *val, void *ptr) {
	GQueue *q = ptr;
	g_queue_push_tail(q, obj_get(val));
}

void calls_status_tcp(struct callmaster *m, struct control_stream *s) {
	struct stats st;
	GQueue q = G_QUEUE_INIT;
	struct call *c;

	mutex_lock(&m->statslock);
	st = m->stats;
	mutex_unlock(&m->statslock);

	rwlock_lock_r(&m->hashlock);
	g_hash_table_foreach(m->callhash, callmaster_get_all_calls_interator, &q);
	rwlock_unlock_r(&m->hashlock);

	control_stream_printf(s, "proxy %u "UINT64F"/"UINT64F"/"UINT64F"\n",
		g_queue_get_length(&q),
		st.bytes, st.bytes - st.errors,
		st.bytes * 2 - st.errors);

	while (q.head) {
		c = g_queue_pop_head(&q);
		call_status_iterator(c, s);
		obj_put(c);
	}
}




static void calls_dump_iterator(void *key, void *val, void *ptr) {
	struct call *c = val;
	struct callmaster *m = c->callmaster;

	redis_update(c, m->conf.redis);
}

void calls_dump_redis(struct callmaster *m) {
	if (!m->conf.redis)
		return;

	mylog(LOG_DEBUG, "Start dumping all call data to Redis...\n");
	redis_wipe_mod(m->conf.redis);
	g_hash_table_foreach(m->callhash, calls_dump_iterator, NULL);
	mylog(LOG_DEBUG, "Finished dumping all call data to Redis\n");
}

void callmaster_config(struct callmaster *m, struct callmaster_config *c) {
	m->conf = *c;
}


enum transport_protocol transport_protocol(const str *s) {
	int i;

	if (!s || !s->s)
		goto out;

	for (i = PROTO_UNKNOWN + 1; i < __PROTO_LAST; i++) {
		if (strlen(transport_protocol_strings[i]) != s->len)
			continue;
		if (strncasecmp(transport_protocol_strings[i], s->s, s->len))
			continue;
		return i;
	}

out:
	return PROTO_UNKNOWN;
}

static void call_ng_process_flags(struct sdp_ng_flags *out, bencode_item_t *input) {
	bencode_item_t *list, *it;
	int diridx;
	str s;

	ZERO(*out);

	if ((list = bencode_dictionary_get_expect(input, "flags", BENCODE_LIST))) {
		for (it = list->child; it; it = it->sibling) {
			if (!bencode_strcmp(it, "trust address"))
				out->trust_address = 1;
			else if (!bencode_strcmp(it, "symmetric"))
				out->symmetric = 1;
			else if (!bencode_strcmp(it, "asymmetric"))
				out->asymmetric = 1;
			else if (!bencode_strcmp(it, "trust-address"))
				out->trust_address = 1;
		}
	}

	if ((list = bencode_dictionary_get_expect(input, "replace", BENCODE_LIST))) {
		for (it = list->child; it; it = it->sibling) {
			if (!bencode_strcmp(it, "origin"))
				out->replace_origin = 1;
			else if (!bencode_strcmp(it, "session connection"))
				out->replace_sess_conn = 1;
			else if (!bencode_strcmp(it, "session-connection"))
				out->replace_sess_conn = 1;
		}
	}

	/* XXX convert to a "desired-family" kinda thing instead */
	diridx = 0;
	if ((list = bencode_dictionary_get_expect(input, "direction", BENCODE_LIST))) {
		for (it = list->child; it && diridx < 2; it = it->sibling) {
			if (!bencode_strcmp(it, "internal"))
				out->directions[diridx++] = DIR_INTERNAL;
			else if (!bencode_strcmp(it, "external"))
				out->directions[diridx++] = DIR_EXTERNAL;
		}
	}

	list = bencode_dictionary_get_expect(input, "received from", BENCODE_LIST);
	if (!list)
		list = bencode_dictionary_get_expect(input, "received-from", BENCODE_LIST);
	if (list && (it = list->child)) {
		bencode_get_str(it, &out->received_from_family);
		bencode_get_str(it->sibling, &out->received_from_address);
	}

	if (bencode_dictionary_get_str(input, "ICE", &s)) {
		if (!str_cmp(&s, "remove"))
			out->ice_remove = 1;
		else if (!str_cmp(&s, "force"))
			out->ice_force = 1;
	}

	bencode_dictionary_get_str(input, "transport protocol", &out->transport_protocol_str);
	if (!out->transport_protocol_str.s)
		bencode_dictionary_get_str(input, "transport-protocol", &out->transport_protocol_str);
	out->transport_protocol = transport_protocol(&out->transport_protocol_str);
	bencode_dictionary_get_str(input, "media address", &out->media_address);
}

static const char *call_offer_answer_ng(bencode_item_t *input, struct callmaster *m,
		bencode_item_t *output, enum call_opmode opmode)
{
	str sdp, fromtag, totag = STR_NULL, callid;
	char *errstr;
	GQueue parsed = G_QUEUE_INIT;
	GQueue streams = G_QUEUE_INIT;
	struct call *call;
	struct call_monologue *monologue;
	int ret;
	struct sdp_ng_flags flags;
	struct sdp_chopper *chopper;

	if (!bencode_dictionary_get_str(input, "sdp", &sdp))
		return "No SDP body in message";
	if (!bencode_dictionary_get_str(input, "call-id", &callid))
		return "No call-id in message";
	if (!bencode_dictionary_get_str(input, "from-tag", &fromtag))
		return "No from-tag in message";
	if (opmode == OP_ANSWER) {
		if (!bencode_dictionary_get_str(input, "to-tag", &totag))
			return "No to-tag in message";
	}
	//bencode_dictionary_get_str(input, "via-branch", &viabranch);
	//log_info = &viabranch;

	if (sdp_parse(&sdp, &parsed))
		return "Failed to parse SDP";

	call_ng_process_flags(&flags, input);

	errstr = "Incomplete SDP specification";
	if (sdp_streams(&parsed, &streams, &flags))
		goto out;

	call = call_get_opmode(&callid, m, opmode);
	errstr = "Unknown call-id";
	if (!call)
		goto out;
	//log_info = &viabranch;

	monologue = call_get_mono_dialogue(call, &fromtag, &totag);

	chopper = sdp_chopper_new(&sdp);
	bencode_buffer_destroy_add(output->buffer, (free_func_t) sdp_chopper_destroy, chopper);
	/* XXX return value */
	monologue_offer_answer(monologue, &streams);
	ret = sdp_replace(chopper, &parsed, monologue, &flags);

	rwlock_unlock_w(&call->master_lock);
	redis_update(call, m->conf.redis);
	obj_put(call);

	errstr = "Error rewriting SDP";
	if (ret)
		goto out;

	bencode_dictionary_add_iovec(output, "sdp", &g_array_index(chopper->iov, struct iovec, 0),
		chopper->iov_num, chopper->str_len);
	bencode_dictionary_add_string(output, "result", "ok");

	errstr = NULL;
out:
	sdp_free(&parsed);
	streams_free(&streams);
	log_info = NULL;

	return errstr;
}

const char *call_offer_ng(bencode_item_t *input, struct callmaster *m, bencode_item_t *output) {
	return call_offer_answer_ng(input, m, output, OP_OFFER);
}

const char *call_answer_ng(bencode_item_t *input, struct callmaster *m, bencode_item_t *output) {
	return call_offer_answer_ng(input, m, output, OP_ANSWER);
}

const char *call_delete_ng(bencode_item_t *input, struct callmaster *m, bencode_item_t *output) {
	str fromtag, totag, viabranch, callid;
	bencode_item_t *flags, *it;
	int fatal = 0;

	if (!bencode_dictionary_get_str(input, "call-id", &callid))
		return "No call-id in message";
	if (!bencode_dictionary_get_str(input, "from-tag", &fromtag))
		return "No from-tag in message";
	bencode_dictionary_get_str(input, "to-tag", &totag);
	bencode_dictionary_get_str(input, "via-branch", &viabranch);

	flags = bencode_dictionary_get_expect(input, "flags", BENCODE_LIST);
	if (flags) {
		for (it = flags->child; it; it = it->sibling) {
			if (!bencode_strcmp(it, "fatal"))
				fatal = 1;
		}
	}

	if (call_delete_branch(m, &callid, &viabranch, &fromtag, &totag, output)) {
		if (fatal)
			return "Call-ID not found or tags didn't match";
		bencode_dictionary_add_string(output, "warning", "Call-ID not found or tags didn't match");
	}

	bencode_dictionary_add_string(output, "result", "ok");
	return NULL;
}

void callmaster_exclude_port(struct callmaster *m, u_int16_t p) {
	mutex_lock(&m->portlock);
	bit_array_set(m->ports_used, p);
	mutex_unlock(&m->portlock);
}

#if 0
static bencode_item_t *peer_address(bencode_buffer_t *b, struct stream *s) {
	bencode_item_t *d;
	char buf[64];

	d = bencode_dictionary(b);
	if (IN6_IS_ADDR_V4MAPPED(&s->ip46)) {
		bencode_dictionary_add_string(d, "family", "IPv4");
		inet_ntop(AF_INET, &(s->ip46.s6_addr32[3]), buf, sizeof(buf));
	}
	else {
		bencode_dictionary_add_string(d, "family", "IPv6");
		inet_ntop(AF_INET6, &s->ip46, buf, sizeof(buf));
	}
	bencode_dictionary_add_string_dup(d, "address", buf);
	bencode_dictionary_add_integer(d, "port", s->port);

	return d;
}
#endif

#if 0
static bencode_item_t *stats_encode(bencode_buffer_t *b, struct stats *s) {
	bencode_item_t *d;

	d = bencode_dictionary(b);
	bencode_dictionary_add_integer(d, "packets", s->packets);
	bencode_dictionary_add_integer(d, "bytes", s->bytes);
	bencode_dictionary_add_integer(d, "errors", s->errors);
	return d;
}
#endif

#if 0
static bencode_item_t *streamrelay_stats(bencode_buffer_t *b, struct packet_stream *ps) {
	bencode_item_t *d;

	d = bencode_dictionary(b);

	// XXX
	//bencode_dictionary_add(d, "counters", stats_encode(b, &r->stats));
	//bencode_dictionary_add(d, "peer address", peer_address(b, &r->peer));
	//bencode_dictionary_add(d, "advertised peer address", peer_address(b, &r->peer_advertised));

	bencode_dictionary_add_integer(d, "local port", ps->fd.localport);

	return d;
}
#endif

#if 0
static bencode_item_t *rtp_rtcp_stats(bencode_buffer_t *b, struct stats *rtp, struct stats *rtcp) {
	bencode_item_t *s;
	s = bencode_dictionary(b);
	bencode_dictionary_add(s, "rtp", stats_encode(b, rtp));
	bencode_dictionary_add(s, "rtcp", stats_encode(b, rtcp));
	return s;
}
#endif

#if 0
XXX
static bencode_item_t *peer_stats(bencode_buffer_t *b, struct peer *p) {
	bencode_item_t *d, *s;

	d = bencode_dictionary(b);

	bencode_dictionary_add_str_dup(d, "tag", &p->tag);
	if (p->codec)
		bencode_dictionary_add_string(d, "codec", p->codec);
	if (p->kernelized)
		bencode_dictionary_add_string(d, "status", "in kernel");
	else if (p->confirmed)
		bencode_dictionary_add_string(d, "status", "confirmed peer address");
	else if (p->filled)
		bencode_dictionary_add_string(d, "status", "known but unconfirmed peer address");
	else
		bencode_dictionary_add_string(d, "status", "unknown peer address");

	s = bencode_dictionary_add_dictionary(d, "stats");
	bencode_dictionary_add(s, "rtp", streamrelay_stats(b, &p->rtps[0]));
	bencode_dictionary_add(s, "rtcp", streamrelay_stats(b, &p->rtps[1]));

	return d;
}

static void ng_stats_cb(struct peer *p, struct peer *px, void *streams) {
	bencode_item_t *stream;

	stream = bencode_list_add_list(streams);
	bencode_list_add(stream, peer_stats(stream->buffer, p));
	bencode_list_add(stream, peer_stats(stream->buffer, px));
}
#endif

/* call must be locked */
static void ng_call_stats(struct call *call, const str *fromtag, const str *totag, bencode_item_t *output) {
	//bencode_item_t *streams, *dict;
//	struct call_stats stats;

//	bencode_dictionary_add_integer(output, "created", call->created);

	//streams = bencode_dictionary_add_list(output, "streams");
	//stats_query(call, fromtag, totag, &stats, ng_stats_cb, streams); XXX

//	dict = bencode_dictionary_add_dictionary(output, "totals");
//	bencode_dictionary_add(dict, "input", rtp_rtcp_stats(output->buffer, &stats.totals[0], &stats.totals[1]));
//	bencode_dictionary_add(dict, "output", rtp_rtcp_stats(output->buffer, &stats.totals[2], &stats.totals[3]));
}

const char *call_query_ng(bencode_item_t *input, struct callmaster *m, bencode_item_t *output) {
	str callid, fromtag, totag;
	struct call *call;

	if (!bencode_dictionary_get_str(input, "call-id", &callid))
		return "No call-id in message";
	call = call_get_opmode(&callid, m, OP_OTHER);
	if (!call)
		return "Unknown call-id";
	bencode_dictionary_get_str(input, "from-tag", &fromtag);
	bencode_dictionary_get_str(input, "to-tag", &totag);

	bencode_dictionary_add_string(output, "result", "ok");
	ng_call_stats(call, &fromtag, &totag, output);
	rwlock_unlock_w(&call->master_lock);

	return NULL;
}
