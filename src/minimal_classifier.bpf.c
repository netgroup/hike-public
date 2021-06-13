
#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <linux/errno.h>

#define HIKE_DEBUG 1
#include "hike_vm.h"
#include "parse_helpers.h"

#define MAP_IPV6_SIZE	64
bpf_map(map_ipv6, HASH, struct in6_addr, __u32, MAP_IPV6_SIZE);

struct ipv6_info {
	int nexthdr;
	__u8 __pad[4];
};

static __always_inline
int __hvxdp_handle_ipv6(struct hdr_cursor *cur, struct xdp_md *ctx)
{
	struct ipv6_info *info;
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

	/* save the nexthdr into the shared hike_pcpu_shmem data chunk */
	info = hike_pcpu_shmem();
	if (!info)
		/* TODO: this should be considered an error */
		goto pass;

	/* this value will be available to HIKe Chains :-o */
	info->nexthdr = nexthdr;

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
		DEBUG_PRINT("HIKe VM Classifier passthrough for proto=%x",
			    bpf_htons(eth_type));
		goto out;
	}

	/* default policy allows any unrecognized packed... */
out:
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
