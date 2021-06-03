
#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <linux/errno.h>

#define HIKE_DEBUG 1
#include "hike_vm.h"

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

/* header cursor to keep track of current parsing position within the packet */
struct hdr_cursor {
	struct xdp_md *ctx;

	int dataoff;
	int mhoff;
	int nhoff;
	int thoff;
};

/* the maximum offset at which a generic protocol is considered to be valid
 * from the beginning (head) of the hdr_cursor.
 */
#define PROTO_OFF_MAX 0x7ff

static __always_inline void cur_reset_mac_header(struct hdr_cursor *cur)
{
	cur->mhoff = cur->dataoff;
}

static __always_inline void cur_reset_network_header(struct hdr_cursor *cur)
{
	cur->nhoff = cur->dataoff;
}

static __always_inline void cur_reset_transport_header(struct hdr_cursor *cur)
{
	cur->thoff = cur->dataoff;
}

static __always_inline void *cur_head(struct hdr_cursor *cur)
{
	return (void *)((long)cur->ctx->data);
}

static __always_inline void *cur_data(struct hdr_cursor *cur)
{
	return cur_head(cur) + cur->dataoff;
}

static __always_inline int cur_set_data(struct hdr_cursor *cur, int off)
{
	if (off < 0 || off > PROTO_OFF_MAX)
		return -EINVAL;

	cur->dataoff = off & PROTO_OFF_MAX;

	return 0;
}

static __always_inline void *cur_tail(struct hdr_cursor *cur)
{
	return (void *)((long)cur->ctx->data_end);
}

static __always_inline void *cur_mac_header(struct hdr_cursor *cur)
{
	return cur_head(cur) + cur->mhoff;
}

static __always_inline void *cur_network_header(struct hdr_cursor *cur)
{
	return cur_head(cur) + cur->nhoff;
}

static __always_inline void *cur_transport_header(struct hdr_cursor *cur)
{
	return cur_head(cur) + cur->thoff;
}

static __always_inline int
__cur_update(struct hdr_cursor *cur, struct xdp_md * ctx)
{
	cur->ctx = ctx;

	return 0;
}

#define cur_touch	__cur_update

static __always_inline void
cur_init(struct hdr_cursor *cur, struct xdp_md * ctx)
{
	__cur_update(cur, ctx);
	cur->dataoff = 0;
	cur_reset_mac_header(cur);
	cur_reset_network_header(cur);
	cur_reset_transport_header(cur);
}

static __always_inline int
__check_proto_offsets(struct hdr_cursor *cur)
{
	if (cur->dataoff < 0 || cur->dataoff > PROTO_OFF_MAX)
		goto error;

	if (cur->mhoff < 0 || cur->mhoff > PROTO_OFF_MAX)
		goto error;

	if (cur->nhoff < 0 || cur->nhoff > PROTO_OFF_MAX)
		goto error;

	if (cur->thoff < 0 || cur->thoff > PROTO_OFF_MAX)
		goto error;

	return 0;

error:
	return -EINVAL;

}

static __always_inline int
cur_update_pointers(struct hdr_cursor *cur, struct xdp_md * ctx)
{
	int rc;

	rc =__cur_update(cur, ctx);
	if (rc < 0)
		return rc;

	return __check_proto_offsets(cur);
}

static __always_inline int
cur_adjust_proto_offsets(struct hdr_cursor *cur, int off)
{
	cur->dataoff += off;
	cur->mhoff += off;
	cur->nhoff += off;
	cur->thoff += off;

	return __check_proto_offsets(cur);
}

static __always_inline int
cur_update_pointers_after_head_expand(struct hdr_cursor *cur,
				      struct xdp_md * ctx, int head_off)
{
	int rc;

	rc = __cur_update(cur, ctx);
	if (rc < 0)
		return rc;

	return cur_adjust_proto_offsets(cur, head_off);
}

#define		__may_pull(__ptr, __len, __data_end)			\
			(((void *)(__ptr)) + (__len) <= (__data_end))

#define 	__may_pull_hdr(__hdr, __data_end)			\
			((__hdr) + 1 <= (__data_end))

#define 	__pull(__cur, __len)					\
			((__cur)->dataoff += (__len))

static __always_inline int cur_may_pull(struct hdr_cursor *cur, int len)
{
	void *tail;
	void *data;

	if (cur->dataoff < 0 || cur->dataoff > PROTO_OFF_MAX)
		return 0;

	cur->dataoff &= PROTO_OFF_MAX;
	data = cur_data(cur);
	tail = cur_tail(cur);

	return __may_pull(data, len, tail);
}

static __always_inline void *cur_pull(struct hdr_cursor *cur, int len)
{
	if (!cur_may_pull(cur, len))
		return NULL;

	__pull(cur, len);

	return cur_data(cur);
}

static __always_inline void *
cur_header_pointer(struct hdr_cursor *cur, int off, int len)
{
	void *head = cur_head(cur);
	void *tail = cur_tail(cur);
	int __off = off + len;

	if (__off < 0 || __off > PROTO_OFF_MAX)
		goto error;

	/* to make the verifier happy... */
	len &= PROTO_OFF_MAX;
	off &= PROTO_OFF_MAX;

	/* overflow for the packet */
	if (!__may_pull(head + off, len, tail))
		goto error;

	return head + off;

error:
	return NULL;
}

static __always_inline void *cur_push(struct hdr_cursor *cur, int len)
{
	int off;

	if (len < 0)
		goto error;

	off = (cur->dataoff - len);
	if (off < 0)
		goto error;

	cur->dataoff = off & PROTO_OFF_MAX;
	if (!cur_may_pull(cur, len))
		goto error;

	return cur_data(cur);

error:
	return NULL;
}

static __always_inline int parse_ethhdr(struct hdr_cursor *cur,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = cur_data(cur);
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (!cur_may_pull(cur, sizeof(*eth)))
		return -ENOBUFS;

	if (ethhdr)
		*ethhdr = eth;

	vlh = cur_pull(cur, sizeof(*eth));
	h_proto = eth->h_proto;

	/* Use loop unrolling to avoid the verifier restriction on loops;
	 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
	 */
#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		if (!cur_may_pull(cur, sizeof(*vlh)))
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		cur_pull(cur, sizeof(*vlh));
	}

	return h_proto; /* network-byte-order */
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *cur,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = cur_data(cur);

	/* Pointer-arithmetic bounds check; pointer +1 points to after end of
	 * thing being pointed to. We will be using this style in the remainder
	 * of the tutorial.
	 */
	if (!cur_may_pull(cur, sizeof(*ip6h)))
		return -ENOBUFS;

	if (ip6hdr)
		*ip6hdr = ip6h;

	cur_pull(cur, sizeof(*ip6h));

	return ip6h->nexthdr;
}


#define MAP_IPV6_SIZE	64
bpf_map(map_ipv6, HASH, struct in6_addr, __u32, MAP_IPV6_SIZE);

static __always_inline
int __hvxdp_handle_ipv6(struct hdr_cursor *cur, struct xdp_md *ctx)
{
	struct in6_addr *key;
	struct ipv6hdr *ip6h;
	__u32 *chain_id;
	int nexthdr;
	int rc;

	nexthdr = parse_ip6hdr(cur, &ip6h);
	if (!ip6h || nexthdr < 0)
		goto pass;

	cur_reset_transport_header(cur);

	/* let's find out the chain id associated with the IPv6 DA */
	key = &ip6h->daddr;
	chain_id = bpf_map_lookup_elem(&map_ipv6, key);
	if (!chain_id)
		/* value not found, deliver the packet to the kernel */
		goto pass;

	DEBUG_PRINT("HIKe VM invoking Chain ID=0x%x", *chain_id);

	rc = hike_chain_boostrap(ctx, *chain_id);
	/* fallback */
	if (rc < 0)
		DEBUG_PRINT("HIKe VM returned error code=%d", rc);

pass:
	return XDP_PASS;
}

__section("hike_classifier")
int __hike_classifier(struct xdp_md *ctx)
{
	struct hdr_cursor cur;
	struct ethhdr *eth;
	__be16 eth_type;
	__u16 proto;

	cur_init(&cur, ctx);

	eth_type = parse_ethhdr(&cur, &eth);
	if (!eth || eth_type < 0)
		goto out;

	/* set the network header */
	cur_reset_network_header(&cur);

	proto = bpf_htons(eth_type);
	switch (proto) {
	case ETH_P_IPV6:
		return __hvxdp_handle_ipv6(&cur, ctx);
	case ETH_P_IP:
		/* fallthrough */
	default:
		/* TODO: IPv4 for the moment is not supported */
		DEBUG_PRINT("HIKe VM Classifier passthrough for proto=%x\n",
			    bpf_htons(eth_type));
		goto out;
	}

	/* default policy allows any unrecognized packed... */
out:
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
