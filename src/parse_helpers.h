
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


#define PKT_INFO_CB_SIZE	48

/* NextHeader field of IPv6 header
 * see: https://elixir.bootlin.com/linux/latest/source/include/net/ipv6.h#L32
 */

#define NEXTHDR_HOP		0	/* Hop-by-hop option header. */
#define NEXTHDR_IPV4		4	/* IPv4 in IPv6 */
#define NEXTHDR_TCP		6	/* TCP segment. */
#define NEXTHDR_UDP		17	/* UDP message. */
#define NEXTHDR_IPV6		41	/* IPv6 in IPv6 */
#define NEXTHDR_ROUTING		43	/* Routing header. */
#define NEXTHDR_FRAGMENT	44	/* Fragmentation/reassembly header. */
#define NEXTHDR_GRE		47	/* GRE header. */
#define NEXTHDR_ESP		50	/* Encapsulating security payload. */
#define NEXTHDR_AUTH		51	/* Authentication header. */
#define NEXTHDR_ICMP		58	/* ICMP for IPv6. */
#define NEXTHDR_NONE		59	/* No next header */
#define NEXTHDR_DEST		60	/* Destination options header. */
#define NEXTHDR_SCTP		132	/* SCTP message. */
#define NEXTHDR_MOBILITY	135	/* Mobility header. */

#define NEXTHDR_MAX		255

struct pkt_info {
	struct hdr_cursor cur;
	__u8 cb[PKT_INFO_CB_SIZE];
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

#define ipv6_optlen(p)  (((p)->hdrlen+1) << 3)
#define ipv6_authlen(p) (((p)->hdrlen+2) << 2)

static __always_inline int ipv6_ext_hdr(__u8 nexthdr)
{
	/* find out if nexthdr is an extension header or a protocol */
	return   (nexthdr == NEXTHDR_HOP)	||
		 (nexthdr == NEXTHDR_ROUTING)	||
		 (nexthdr == NEXTHDR_FRAGMENT)	||
		 (nexthdr == NEXTHDR_AUTH)	||
		 (nexthdr == NEXTHDR_NONE)	||
		 (nexthdr == NEXTHDR_DEST);
}

#ifndef IPV6_EXTHDR_DEPTH_MAX
#define IPV6_EXTHDR_DEPTH_MAX	4
#endif

static __always_inline int
ipv6_skip_exthdr(struct xdp_md *ctx, struct hdr_cursor *cur, int *start,
		 __u8 *nexthdrp)
{
	struct ipv6_opt_hdr *hdr;
	__u8 nexthdr = *nexthdrp;
	int i, hdrlen;

	for (i = 0; i < IPV6_EXTHDR_DEPTH_MAX; ++i) {
		if (!ipv6_ext_hdr(nexthdr)) {
			*nexthdrp = nexthdr;
			return nexthdr;
		}

		if (nexthdr == NEXTHDR_NONE)
			return -EPERM;
		if (nexthdr == NEXTHDR_FRAGMENT)
			return -EOPNOTSUPP;

		hdr = (struct ipv6_opt_hdr *)cur_header_pointer(ctx, cur,
								*start,
								sizeof(*hdr));
		if (!hdr)
			return -EINVAL;

		if (nexthdr == NEXTHDR_AUTH)
			hdrlen = ipv6_authlen(hdr);
		else
			hdrlen = ipv6_optlen(hdr);

		nexthdr = hdr->nexthdr;
		*start += hdrlen;
	}

	return -ELOOP;
}

#endif /* end of #ifdef for include header file */
