#ifndef _IPV6_HSET_H
#define _IPV6_HSET_H



#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/errno.h>

#include "map.h"

#define HIKE_IPV6_HSET_MAX		4096

/* FIXME: make this value adjustable */
// expiration timer for the blacklist
#define HIKE_IPV6_HSET_EXP_TIMEOUT_NS 	60000000000ul /* 60 secs */

#define	IPV6_HSET_ACTION_LOOKUP			      0
#define	IPV6_HSET_ACTION_ADD			        1
#define	IPV6_HSET_ACTION_LOOKUP_AND_CLEAN	2

struct ipv6_hset_srcdst_key {
	struct in6_addr saddr;
	struct in6_addr daddr;
};

struct ipv6_hset_src_key {
	struct in6_addr saddr;
};

struct ipv6_hset_dst_key {
	struct in6_addr daddr;
};


struct ipv6_hset_value {
	__u64 cts_ns;		/* creation time stamp in ns */
	__u64 timeout_ns;
};

/* hdr_cursor->nhoff must be set and must point to network header */
static __always_inline int
ipv6_hset_srcdst_get_key(struct xdp_md *ctx, struct hdr_cursor *cur,
			 struct ipv6_hset_srcdst_key *key)
{
	struct ipv6hdr *hdr;

	/* ctx is injected by the HIKe VM */
	hdr = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff,
						   sizeof(*hdr));
	if (unlikely(!hdr))
		return -EINVAL;

	key->saddr = hdr->saddr;
	key->daddr = hdr->daddr;

	return 0;
}

/* hdr_cursor->nhoff must be set and must point to network header */
static __always_inline int
ipv6_hset_src_get_key(struct xdp_md *ctx, struct hdr_cursor *cur,
			 struct ipv6_hset_src_key *key)
{
	struct ipv6hdr *hdr;

	/* ctx is injected by the HIKe VM */
	hdr = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff,
						   sizeof(*hdr));
	if (unlikely(!hdr))
		return -EINVAL;

	key->saddr = hdr->saddr;

	return 0;
}

/* hdr_cursor->nhoff must be set and must point to network header */
static __always_inline int
ipv6_hset_dst_get_key(struct xdp_md *ctx, struct hdr_cursor *cur,
			 struct ipv6_hset_dst_key *key)
{
	struct ipv6hdr *hdr;

	/* ctx is injected by the HIKe VM */
	hdr = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff,
						   sizeof(*hdr));
	if (unlikely(!hdr))
		return -EINVAL;

	key->daddr = hdr->daddr;

	return 0;
}


#endif