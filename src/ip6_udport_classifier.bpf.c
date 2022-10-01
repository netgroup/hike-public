
#define UDP_DPORT		862

#define __HIKE_PROG_NAME_PREFIX	ip6_udport
#define HIKE_PROG_NAME	\
	EVAL_CAT_4(__HIKE_PROG_NAME_PREFIX, _, UDP_DPORT, _cls)

#ifndef HIKE_PRINT_LEVEL
/* DEBUG level is set by default */
#define HIKE_PRINT_LEVEL	HIKE_PRINT_LEVEL_DEBUG
#endif

#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <linux/errno.h>

#include "hike_vm.h"
#include "parse_helpers.h"

#define __FUNC_NAME_CLS EVAL_CAT_2(__, HIKE_PROG_NAME)

#define IP6_UDPORT_CLS()				\
	__section(stringify(HIKE_PROG_NAME))		\
	int __FUNC_NAME_CLS(struct xdp_md *ctx)

#define IP6_UDPORT_CLS_MAP	EVAL_CAT_2(__HIKE_PROG_NAME_PREFIX, _cls_map)
#define IP6_UDPORT_CLS_MAP_SIZE	1

#define IP6_UDPORT_CLS_INDEX	0

bpf_map(IP6_UDPORT_CLS_MAP, ARRAY, __u32, __u32, IP6_UDPORT_CLS_MAP_SIZE);

/* NOTE: use this function only in one place otherwise the compiler will emit a
 * non-inline function.
 */
static __always_inline
int ____udp_invoke_chain(struct xdp_md *ctx, struct hdr_cursor *cur)
{
	const __u32 key = IP6_UDPORT_CLS_INDEX;
	__u32 *chain_id;
	int rc;

	/* load the Chain-ID directly from the classifier config map */
	chain_id = bpf_map_lookup_elem(&IP6_UDPORT_CLS_MAP, &key);
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
	return -EINVAL;
}

static __always_inline
int udp_filter(struct xdp_md *ctx, struct hdr_cursor *cur, __u16 dport)
{
	struct udphdr *udph;
	__u16 dest;

	if (unlikely(!cur_may_pull(ctx, cur, sizeof(*udph)))) {
		hike_pr_err("cannot parse the UDP header");
		return -ENOBUFS;
	}

	udph = (struct udphdr *)cur_data(ctx, cur);

	dest = bpf_ntohs(udph->dest);
	if (dest != dport)
		return 0;

	return ____udp_invoke_chain(ctx, cur);
}

static __always_inline
int parse_srh(struct xdp_md *ctx, struct hdr_cursor *cur,
	      struct ipv6_sr_hdr **hdr)
{
	struct ipv6_sr_hdr *srh;
	int nexthdr;
	int srhlen;

	if (unlikely(!cur_may_pull(ctx, cur, sizeof(*srh))))
		goto err;

	srh = (struct ipv6_sr_hdr *)cur_data(ctx, cur);
	nexthdr = srh->nexthdr;

	srhlen = ipv6_optlen(srh);
	if (unlikely(!cur_may_pull(ctx, cur, srhlen)))
		goto err;

	if (hdr)
		*hdr = srh;

	cur_pull(ctx, cur, srhlen);

	return nexthdr;

err:
	hike_pr_err("cannot parse the SR header");
	return -ENOBUFS;
}

static __always_inline
int ip6_core(struct xdp_md *ctx, struct hdr_cursor *cur, __u16 dport)
{
	int nexthdr;

	nexthdr = parse_ip6hdr(ctx, cur, NULL);
	if (unlikely(nexthdr < 0))
		return nexthdr;

	cur_reset_transport_header(cur);

	if (nexthdr == IPPROTO_ROUTING) {
		nexthdr = parse_srh(ctx, cur, NULL);
		if (unlikely(nexthdr < 0))
			return nexthdr;

		cur_reset_transport_header(cur);
	}

	if (nexthdr != IPPROTO_UDP)
		return 0;

	return udp_filter(ctx, cur, dport);
}

static __always_inline int parse_packet(struct xdp_md *ctx, __u16 dport)
{
	struct hdr_cursor *cur;
	struct pkt_info *info;
	__be16 eth_type;
	__u16 proto;

	info = hike_pcpu_shmem();
	if (unlikely(!info)) {
		hike_pr_alert("cannot get access to pkt_info");
		return -ENOMEM;
	}

	cur = pkt_info_cur(info);
	cur_init(cur);

	/* set the mac header */
	cur_reset_mac_header(cur);

	eth_type = parse_ethhdr(ctx, cur, NULL);
	if (unlikely(eth_type < 0)) {
		hike_pr_err("cannot parse the ethernet header");
		return (int)eth_type;
	}

	/* set the network header */
	cur_reset_network_header(cur);

	proto = bpf_ntohs(eth_type);
	switch (proto) {
	case ETH_P_IPV6:
		return ip6_core(ctx, cur, dport);
	case ETH_P_IP:
	default:
		hike_pr_debug("Passthrough for protocol=%x", proto);
		break;
	}

	return 0;
}

IP6_UDPORT_CLS()
{
	int rc;

	rc = parse_packet(ctx, UDP_DPORT);
	if (unlikely(rc)) {
		hike_pr_err("packet is discarded due an error");
		return XDP_ABORTED;
	}

	return XDP_PASS;
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";
