
#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <linux/errno.h>

/* HIKe Chain IDs and XDP eBPF/HIKe programs ID. For semplicity, we include
 * also RAW ID programs for eBPF Raw.
 */
#include "minimal.h"

#include "map.h"
#include "parse_helpers.h"

#ifdef HIKE_DEBUG
#undef HIKE_DEBUG
#endif

#define HIKE_DEBUG 0

/* included only for DEBUG_PRINT; TODO: factor out the DEBUG_PRINT in a single
 * file so that we do not have to import the while VM .h file.
 */
#if HIKE_DEBUG == 1
#define DEBUG_PRINT(...)					\
	do{							\
			bpf_printk(__VA_ARGS__);		\
	} while (0)
#else
#define DEBUG_PRINT(...) do {} while (0)
#endif

#define __stringify(X)		#X
#define stringify(X)		__stringify(X)

#ifndef __section
#define __section(NAME)						\
	__attribute__((section(NAME), used))
#endif

#ifndef __section_tail
#define __section_tail(ID, KEY)					\
	__section(__stringify(ID) "/" __stringify(KEY))
#endif

/* -------------------------------------------------------------------------- */

#define IP6_COUNTER_MAP_SIZE	16
bpf_map(ip6_cnt_map, PERCPU_HASH, struct in6_addr, __u32, IP6_COUNTER_MAP_SIZE);

static __always_inline
int __raw_handle_ipv6(struct xdp_md *ctx, struct hdr_cursor *cur)
{
	struct in6_addr *key;
	struct ipv6hdr *ip6h;
	__u32 *counter;
	int nexthdr;

	nexthdr = parse_ip6hdr(ctx, cur, &ip6h);
	if (!ip6h || nexthdr < 0)
		return XDP_PASS;

	cur_reset_transport_header(cur);

	/* let's find out the chain id associated with the IPv6 DA */
	key = &ip6h->daddr;
	counter = bpf_map_lookup_elem(&ip6_cnt_map, key);
	if (!counter)
		/* value not found, deliver the packet to the kernel */
		goto out;

	*counter = *counter + 1;

	DEBUG_PRINT("IPv6 Counter value for given address=%d",  *counter);

out:
	return XDP_PASS;
}

__section("raw_classifier")
int __raw_classifier(struct xdp_md *ctx)
{
	struct hdr_cursor cur;
	struct ethhdr *eth;
	__be16 eth_type;
	__u16 proto;

	cur_init(&cur);

	eth_type = parse_ethhdr(ctx, &cur, &eth);
	if (!eth || eth_type < 0)
		return XDP_ABORTED;

	/* set the network header */
	cur_reset_network_header(&cur);

	proto = bpf_htons(eth_type);
	switch (proto) {
	case ETH_P_IPV6:
		return __raw_handle_ipv6(ctx, &cur);
	case ETH_P_IP:
		/* fallthrough */
	default:
		DEBUG_PRINT("RAW: raw_classifier passthrough for proto=%x",
			    bpf_htons(eth_type));
		break;
	}

	/* default policy allows any unrecognized packet... */
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
