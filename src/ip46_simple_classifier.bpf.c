
#define HIKE_PROG_NAME ip46_simp_cls

#ifndef HIKE_PRINT_LEVEL
#define HIKE_PRINT_LEVEL	7 /* DEBUG level is set by default */
#endif

#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <linux/errno.h>
#include <sys/types.h>
#include <sys/socket.h>

/* HIKe Chain IDs and XDP eBPF/HIKe programs IDs */
#include "minimal.h"

#include "hike_vm.h"
#include "parse_helpers.h"

#define __FUNC_NAME_CLS EVAL_CAT_2(__, HIKE_PROG_NAME)

#define HIKE_CLS()					\
	__section(stringify(HIKE_PROG_NAME))		\
	int __FUNC_NAME_CLS(struct xdp_md *ctx)

#define IP46_SIMP_CLS_MAP	ip46_simp_cls_map

enum {
	CLS_UNSPEC_KEY = 0,
	CLS_IP4_KEY,
	CLS_IP6_KEY,

	__CLS_PROTO_MAX,
};

#define CLS_PROTO_MAX (__CLS_PROTO_MAX - 1)
#define IP46_SIMP_CLS_MAP_SIZE (CLS_PROTO_MAX + 1)

bpf_map(IP46_SIMP_CLS_MAP, ARRAY, __u32, __u32, IP46_SIMP_CLS_MAP_SIZE);

/* NOTE: use this function only in one place otherwise the compiler will emit a
 * non-inline function.
 */
static __always_inline
int ____ip_core_finish(struct xdp_md *ctx, struct hdr_cursor *cur,
		       const __u32 key)
{
	__u32 *chain_id;
	int rc;

	/* load the Chain-ID directly from the classifier config map */
	chain_id = bpf_map_lookup_elem(&IP46_SIMP_CLS_MAP, &key);
	if (unlikely(!chain_id)) {
		/* is supposed to not fail. This is an unrecoverable error. */
		hike_pr_alert("cannot access to internal eBPF Map");
		goto abort;
	}

	hike_pr_debug("HIKe VM invoking Chain ID=0x%x", *chain_id);

	rc = hike_chain_boostrap(ctx, *chain_id);

	/* the fallback behavior of this classifier consists in dropping any
	 * packet that has not been delivered by any of the selected HIKe
	 * Chains in an explicit way.
	 */
	if (unlikely(rc < 0))
		hike_pr_alert("HIKe VM returned error code=%d", rc);

abort:
	hike_pr_err("packet is discarded due an error");

	return XDP_ABORTED;
}

static __always_inline
int ip4_core(struct xdp_md *ctx, struct hdr_cursor *cur, __u32 *key)
{
	int nexthdr;

	nexthdr = parse_ip4hdr(ctx, cur, NULL);
	if (unlikely(nexthdr < 0))
		return nexthdr;

	*key = CLS_IP4_KEY;

	cur_reset_transport_header(cur);

	return 0;
}

static __always_inline
int ip6_core(struct xdp_md *ctx, struct hdr_cursor *cur, __u32 *key)
{
	int nexthdr;

	nexthdr = parse_ip6hdr(ctx, cur, NULL);
	if (unlikely(nexthdr < 0))
		return nexthdr;

	*key = CLS_IP6_KEY;

	cur_reset_transport_header(cur);

	return 0;
}

static __always_inline
int ip_core(struct xdp_md *ctx, struct hdr_cursor *cur, int family)
{
	__u32 key;
	int rc;

	switch(family) {
	case AF_INET:
		rc = ip4_core(ctx, cur, &key);
		if (unlikely(rc < 0)) {
			hike_pr_err("cannot parse the IPv4 header");
			goto pass;
		}
		break;
	case AF_INET6:
		rc = ip6_core(ctx, cur, &key);
		if (unlikely(rc < 0)) {
			hike_pr_err("cannot parse the IPv6 header");
			goto pass;
		}
		break;
	default:
pass:
		hike_pr_warn("unknown AF family %d", family);
		return XDP_PASS;
	}

	return ____ip_core_finish(ctx, cur, key);
}

/* classifier (main entry point) */
HIKE_CLS()
{
	struct pkt_info *info = hike_pcpu_shmem();
	struct hdr_cursor *cur;
	struct ethhdr *eth;
	__be16 eth_type;
	__u16 proto;
	int family;

	if (unlikely(!info)) {
		hike_pr_alert("cannot get access to pkt_info");
		goto abort;
	}

	cur = pkt_info_cur(info);
	cur_init(cur);

	/* set the mac header */
	cur_reset_mac_header(cur);

	eth_type = parse_ethhdr(ctx, cur, &eth);
	if (unlikely(!eth || eth_type < 0)) {
		hike_pr_err("cannot parse the ethernet header");
		goto pass;
	}

	/* set the network header */
	cur_reset_network_header(cur);

	proto = bpf_ntohs(eth_type);
	switch (proto) {
	case ETH_P_IPV6:
		family = AF_INET6;
		break;
	case ETH_P_IP:
		family = AF_INET;
		break;
	default:
		hike_pr_debug("Passthrough for protocol=%x", proto);
pass:
		return XDP_PASS;
	}

	/* It is important here to have a single call to the HIKe Chain
	 * boostrap otherwise the compiler creates a full-fledged ip_core
	 * function (rather than an inlined one).
	 */
	return ip_core(ctx, cur, family);

abort:
	hike_pr_err("packet is discarded due an error");

	return XDP_ABORTED;
}
EXPORT_HIKE_MAP(__FUNC_NAME_CLS, IP46_SIMP_CLS_MAP);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
