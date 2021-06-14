
#ifndef _PARSE_HELPERS_H
#define _PARSE_HELPERS_H

#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/errno.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "hdr_cursor.h"

struct pkt_info {
	struct hdr_cursor cur;
};

static __always_inline struct hdr_cursor *pkt_info_cur(struct pkt_info *info)
{
	return &info->cur;
}

static __always_inline __u8 ipv6_get_dsfield(const struct ipv6hdr *ip6h)
{
	return bpf_ntohs(*(const __be16 *)ip6h) >> 4;
}

static __always_inline
void ipv6_set_dsfield(struct ipv6hdr *const ip6h, __u8 mask, __u8 value)
{
	__be16 *p = (__be16 *)ip6h;

	/* A bit of explaination here, first 32 bits of an IPv6 packet:
	 * --------------------------------------------------------------------
	 * | Version (4 bits) | Traffic Class (8 bits) | Flow Label (20 bits) |
	 * --------------------------------------------------------------------
	 *
	 * we need to write in the Traffic Class, so we have to shift (left)
	 * both mask and value of 4 bits. Then, we need to keep the 4 bits of
	 * version field and the first 4 bits of the Flow Label field. So, here
	 * we have the mask 0xf00f.
	 * At this point it is just a matter of doing the bit-bit AND between
	 * the previous value of *p (the overall first 16 bits of the packet)
	 * with the adjusted mask value. Therefore, we proceed to consider the
	 * dscp value (doing the bit-bit OR).
	 */
	*p = (*p & bpf_htons((((__u16)mask << 4) | 0xf00f))) |
	      bpf_htons((__u16)value << 4);
}

/*
 *	struct vlan_hdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

/* Allow users of header file to redefine VLAN max depth */
#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 4
#endif

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

static __always_inline int
parse_ethhdr(struct xdp_md *ctx, struct hdr_cursor *cur, struct ethhdr **ethhdr)
{
	struct ethhdr *eth = (struct ethhdr *)cur_data(ctx, cur);
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (!cur_may_pull(ctx, cur, sizeof(*eth)))
		return -ENOBUFS;

	if (ethhdr)
		*ethhdr = eth;

	vlh = (struct vlan_hdr *)cur_pull(ctx, cur, sizeof(*eth));
	h_proto = eth->h_proto;

	/* Use loop unrolling to avoid the verifier restriction on loops;
	 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
	 */
#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		if (!cur_may_pull(ctx, cur, sizeof(*vlh)))
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		cur_pull(ctx, cur, sizeof(*vlh));
	}
	return h_proto; /* network-byte-order */
}

static __always_inline int
parse_ip6hdr(struct xdp_md *ctx, struct hdr_cursor *cur,
	     struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = (struct ipv6hdr *)cur_data(ctx, cur);

	/* Pointer-arithmetic bounds check; pointer +1 points to after end of
	 * thing being pointed to. We will be using this style in the remainder
	 * of the tutorial.
	 */
	if (!cur_may_pull(ctx, cur, sizeof(*ip6h)))
		return -ENOBUFS;

	if (ip6hdr)
		*ip6hdr = ip6h;

	cur_pull(ctx, cur, sizeof(*ip6h));

	return ip6h->nexthdr;
}

#endif /* end of #ifdef for include header file */
