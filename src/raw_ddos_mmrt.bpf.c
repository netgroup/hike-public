
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
#include "ip6_kroute.h"

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
#define __section(NAME)							\
	__attribute__((section(NAME), used))
#endif

#ifndef __section_tail
#define __section_tail(ID, KEY)						\
	__section(__stringify(ID) "/" __stringify(KEY))
#endif

#define MAP_IPV6_SIZE	64
bpf_map(map_ipv6, HASH, struct in6_addr, __u32, MAP_IPV6_SIZE);
bpf_map(raw_jmp_map, PROG_ARRAY, __u32, __u32, 8);

#define raw_tail_call(__ctx, __id) \
	bpf_tail_call((__ctx), &raw_jmp_map, (__id))

struct mon_event {
	__u32 key_event;
	__u32 __pad;
};

struct shmem {
	struct pkt_info pinfo;		/* 8 bytes long */
	struct mon_event mevent;	/* 8 bytes long */
};

bpf_map(raw_shmem_map, PERCPU_ARRAY, __u32, struct shmem, 1);

static __always_inline struct shmem *__get_shmem(void)
{
	const __u32 key = 0;

	return bpf_map_lookup_elem(&raw_shmem_map, &key);
}

static __always_inline struct pkt_info *get_pkt_info(void)
{
	struct shmem *mem;

	mem = __get_shmem();
	if (!mem)
		return NULL;

	return &mem->pinfo;
}

#define IPV6_SET_ECN_RAW_PROG_ID	1
#define MON_EVENT_RAW_PROG_ID		2
#define IPV6_KROUTE_RAW_PROG_ID		3

static __always_inline
int __raw_handle_ipv6(struct xdp_md *ctx, struct hdr_cursor *cur)
{
	struct in6_addr *key;
	struct ipv6hdr *ip6h;
	__u32 *raw_prog_id;
	int nexthdr;

	nexthdr = parse_ip6hdr(ctx, cur, &ip6h);
	if (!ip6h || nexthdr < 0)
		return XDP_PASS;

	cur_reset_transport_header(cur);

	/* let's find out the chain id associated with the IPv6 DA */
	key = &ip6h->daddr;
	raw_prog_id = bpf_map_lookup_elem(&map_ipv6, key);
	if (!raw_prog_id)
		/* value not found, deliver the packet to the kernel */
		return XDP_PASS;

	DEBUG_PRINT("RAW: raw_classifier invoking Raw Program ID=0x%x",
		    *raw_prog_id);

	raw_tail_call(ctx, *raw_prog_id);

	/* the fallback behavior of this classifier consists in dropping any
	 * packet that has not been delivered by any of the selected Raw progs
	 * in an explicit way.
	 */
	DEBUG_PRINT("RAW: raw_classifier fallthrough, packet will be dropped");

	return XDP_ABORTED;
}

/* TODO: define __section (to be copied from hike_vm.h */
__section("raw_classifier")
int __raw_classifier(struct xdp_md *ctx)
{
	struct pkt_info *info = get_pkt_info();
	struct hdr_cursor *cur;
	struct ethhdr *eth;
	__be16 eth_type;
	__u16 proto;

	if (!info)
		return XDP_ABORTED;

	cur = pkt_info_cur(info);
	cur_init(cur);

	eth_type = parse_ethhdr(ctx, cur, &eth);
	if (!eth || eth_type < 0)
		return XDP_ABORTED;	

	/* set the network header */
	cur_reset_network_header(cur);

	proto = bpf_htons(eth_type);
	switch (proto) {
	case ETH_P_IPV6:
		return __raw_handle_ipv6(ctx, cur);
	case ETH_P_IP:
		/* fallthrough */
	default:
		DEBUG_PRINT("RAW: raw_classifier passthrough for proto=%x",
			    bpf_htons(eth_type));
		break;
	}

	/* default policy allows any unrecognized packed... */
	return XDP_PASS;
}

__section("raw_ipv6_set_ecn")
int __raw_ipv6_set_ecn(struct xdp_md *ctx)
{
	struct pkt_info *info = get_pkt_info();
	struct hdr_cursor *cur;
	struct ipv6hdr *hdr;

	if (!info)
		goto drop;

	cur = pkt_info_cur(info);

	hdr = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff,
						   sizeof(*hdr));
	if (!hdr)
		goto drop;

	ipv6_set_dsfield(hdr, 0xfe, 1);

	DEBUG_PRINT("RAW: raw_ipv6_set_ecn set ECN");

	raw_tail_call(ctx, MON_EVENT_RAW_PROG_ID);

	/* fallthrough; for this example, we drop the packet notifying the
	 * event using the "ABORTED" return code.
	 */
drop:
	return XDP_ABORTED;
}	

#define MON_PCPU_MAP_MAX	1024
bpf_map(raw_mon_pcpu_map, PERCPU_HASH, __u32, __u64, MON_PCPU_MAP_MAX);

enum { 
	RAW_MON_EVENT_SET_ECN = 3,
};

__section("raw_mon_ecn_event")
int __raw_mon_ecn_event(struct xdp_md *ctx)
{
	__u32 key = RAW_MON_EVENT_SET_ECN;
	__u64 *value;
	__u64 tmp;

	DEBUG_PRINT("RAW: raw_mon_ecn_event");

	value = bpf_map_lookup_elem(&raw_mon_pcpu_map, &key);
	if (likely(value)) {
		*value += 1;
		goto out;
	}

	tmp = 1;
	bpf_map_update_elem(&raw_mon_pcpu_map, &key, &tmp, BPF_NOEXIST);

out:
	raw_tail_call(ctx, IPV6_KROUTE_RAW_PROG_ID);

	/* fallthrough; for this example, we drop the packet notifying the
	 * event using the "ABORTED" return code.
	 */
	return XDP_ABORTED;
}

__section("raw_ipv6_kroute")
int __raw_ipv6_kroute(struct xdp_md *ctx)
{
	struct pkt_info *info = get_pkt_info();
	struct hdr_cursor *cur;
	int rc;

	if (!info)
		goto drop;

	cur = pkt_info_cur(info);

	DEBUG_PRINT("RAW: raw_ipv6_kroute");

	/* lookup with FIB rules */
	rc = __ipv6_route(ctx, cur, 0);

	return rc;

drop:
	return XDP_ABORTED;

}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
