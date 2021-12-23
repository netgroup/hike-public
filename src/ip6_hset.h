#ifndef _IPV6_HSET_H
#define _IPV6_HSET_H



#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/errno.h>
#include <linux/udp.h>

#include "hike_vm.h"
#include "parse_helpers.h"
#include "map.h"

#define HIKE_IPV6_HSET_MAX		4096

/* FIXME: make this value adjustable */
// expiration timer for the blacklist
#define HIKE_IPV6_HSET_EXP_TIMEOUT_NS 	10000000000ul /* 0 secs */

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

struct ipv6_hset_nh {
	__u8 next_header;
};

struct layer_3_4 {
	__u8 priority:4, version:4; /* don't care about little/big endian */
	__u8 flow_lbl[3];
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
	/* udp */
	__be16 source;
	__be16 dest;
	__be16 len;
	__sum16 check;
};

struct udp_dst_port {
	__u16 dst_port;
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

/* hdr_cursor->nhoff must be set and must point to network header */
static __always_inline int
// ipv6_get_nh(struct xdp_md *ctx, struct hdr_cursor *cur)
ipv6_get_nh(struct xdp_md *ctx, struct hdr_cursor *cur, struct ipv6_hset_nh *nh)

{
	struct ipv6hdr *hdr;

	/* ctx is injected by the HIKe VM */
	hdr = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff, sizeof(*hdr));
	if (unlikely(!hdr))
		return -EINVAL;

	nh->next_header = hdr->nexthdr;

	return 0;
}

/* hdr_cursor->nhoff must be set and must point to network header */
static __always_inline int
ipv6_get_udp_port(struct xdp_md *ctx, struct hdr_cursor *cur, struct udp_dst_port *dp)
{
	struct layer_3_4 *layer34;
	// struct ipv6hdr *hdr;

	// hdr = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff, sizeof(*hdr));
	// if (unlikely(!hdr))
	// 	return -EINVAL;

	/* ctx is injected by the HIKe VM */
	layer34 = (struct layer_3_4 *)cur_header_pointer(ctx, cur, cur->nhoff, sizeof(*layer34));
	if (unlikely(!layer34))
		return -EINVAL;

	dp->dst_port = bpf_htons(layer34->dest);

	return 0;
}


#endif