
#define PROG_NAME ip6fwdacc

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

/* turn off any internal function which relies on the HIKE VM Debug
 * infrastructure.
 */
#ifdef HIKE_DEBUG
#undef HIKE_DEBUG
#endif
#define HIKE_DEBUG 0

/* turn on/off debug prints for this raw program */
#define PR_DEBUG 0

/* optimize the mac rewriting operation */
#define MAC_OPZCOPY_ENABLED 1

/* create a map for monitoring debug events */
#define EVENT_MON_DEBUG 0

#define __stringify(X)		#X
#define stringify(X)		__stringify(X)

#if PR_DEBUG == 1
#define pr_debug(...)							\
	do{								\
		bpf_printk(stringify(PROG_NAME)": " __VA_ARGS__);	\
	} while (0)
#else
#define pr_debug(...) do {} while (0)
#endif

#ifndef __section
#define __section(NAME)						\
	__attribute__((section(NAME), used))
#endif

#ifndef __section_tail
#define __section_tail(ID, KEY)					\
	__section(__stringify(ID) "/" __stringify(KEY))
#endif

enum {
	E_UNSPEC = 0,		//0
	E_ETH_ERR,		//1
	E_L3_UNK_PROTO,		//2
	E_IPV4_PROTO,		//3
	E_IPV6_PROTO,		//4
	E_IPV6_ERR,		//5
	E_NOFWD_ELEM,		//6
	E_IDX_REC_ERR,		//7
	/* XXX: add new event here */
	XDP_ACTION,		//8
	/* record the number of events related to a given action */
	E_IFINDEX = 32,
};

#if EVENT_MON_DEBUG > 0
#define EVENT_MAP		event_map
#define EVENT_MAP_SIZE		128

bpf_map(EVENT_MAP, PERCPU_HASH, __u32, __u32, EVENT_MAP_SIZE);

static __always_inline
int __store_ref_event_keyval(__u32 *key, __u32 *value, __u32 flags)
{
	return bpf_map_update_elem(&EVENT_MAP, key, value, flags);
}

static __always_inline
int __store_val_event_keyval(__u32 key, __u32 value, __u32 flags)
{
	return __store_ref_event_keyval(&key, &value, flags);
}

static __always_inline int __record_event(__u32 eventid)
{
	__u32 key = eventid;
	__u32 *value, tmp;

	value = bpf_map_lookup_elem(&EVENT_MAP, &key);
	if (!value) {
		tmp = 0;
		value = &tmp;
	}

	*value += 1;

	return __store_ref_event_keyval(&key, value, BPF_ANY);
}

static __always_inline void record_event(__u32 eventid)
{
	int rc;

	if (eventid >= EVENT_MAP_SIZE)
		goto err;

	rc = __record_event(eventid);
	if (!rc)
		return;
err:
	__record_event(E_IDX_REC_ERR);
}
#else /* EVENT_MON_DEBUG */
static __always_inline
int __store_val_event_keyval(__u32 key, __u32 value, __u32 flags)
{
	return -EOPNOTSUPP;
}

static __always_inline void record_event(__u32 eventid)
{
}
#endif

struct eth_addr {
	__u8 addr[ETH_ALEN];
} __attribute__((packed));

#define IP6_FWD_MAP		ip6_fwd_map
#define IP6_FWD_MAP_SIZE	128

struct fwd_nh_info {
	__u32 ifindex;
	struct eth_addr daddr;
	struct eth_addr saddr;
};

bpf_map(IP6_FWD_MAP, HASH, struct in6_addr, struct fwd_nh_info,
	IP6_FWD_MAP_SIZE);

#if MAC_OPZCOPY_ENABLED > 0
struct __mac_rewrite {
	union {
		struct {
			struct eth_addr addr[2];
		} e1 __attribute__((packed));
		struct {
			__u64 v1;
			__u32 v2;
		} e2 __attribute__((packed));
	} u __attribute__((aligned((2))));
};
#endif

static __always_inline
void __mac_rewrite(struct ethhdr *eth, const struct fwd_nh_info *nh_info)
{
#if MAC_OPZCOPY_ENABLED > 0
	const struct __mac_rewrite *src;
	struct __mac_rewrite *dst;

	src = (struct __mac_rewrite *)&nh_info->daddr;
	dst = (struct __mac_rewrite *)&eth->h_dest;

	dst->u.e2.v1 = src->u.e2.v1;
	dst->u.e2.v2 = src->u.e2.v2;
#else
	memcpy(eth->h_dest, nh_info->daddr.addr, ETH_ALEN);
	memcpy(eth->h_source, nh_info->saddr.addr, ETH_ALEN);
#endif
}

static __always_inline
int __fwd_packet(struct xdp_md *ctx, struct hdr_cursor *cur,
		 const struct fwd_nh_info *nh_info)
{
	struct ethhdr *eth = (struct ethhdr *)cur_mac_header(ctx, cur);
	unsigned char *tail = xdp_md_tail(ctx);
	int action;

	if (unlikely(!__may_pull(eth, sizeof(*eth), tail))) {
		record_event(E_ETH_ERR);
		pr_debug("cannot access to the ethernet header, abort");
		return XDP_ABORTED;
	}

	__mac_rewrite(eth, nh_info);

	action = bpf_redirect(nh_info->ifindex, 0);

	record_event(XDP_ACTION + action);
	__store_val_event_keyval(E_IFINDEX, nh_info->ifindex, BPF_ANY);

	pr_debug("forwarding packet, action %d", action);

	return action;
}

static __always_inline
int __raw_handle_ipv6(struct xdp_md *ctx, struct hdr_cursor *cur)
{
	struct fwd_nh_info *nh_info;
	struct in6_addr *key;
	struct ipv6hdr *ip6h;
	int nexthdr;

	nexthdr = parse_ip6hdr(ctx, cur, &ip6h);
	if (unlikely(!ip6h || nexthdr < 0)) {
		record_event(E_IPV6_ERR);
		pr_debug("cannot parse the IPv6 header, passthrough");
		goto out;
	}

	cur_reset_transport_header(cur);
	key = &ip6h->daddr;

	nh_info = bpf_map_lookup_elem(&IP6_FWD_MAP, key);
	if (!nh_info) {
		record_event(E_NOFWD_ELEM);
		pr_debug("no forwarding cache element is found, passthrough");
		goto out;
	}

	/* we have a match in the forwarding table, let's accelerate the fwd */
	return __fwd_packet(ctx, cur, nh_info);

out:
	return XDP_PASS;
}

__section("raw_ip6_fwdacc")
int __raw_ip6_fwdacc(struct xdp_md *ctx)
{
	struct hdr_cursor cur;
	struct ethhdr *eth;
	__be16 eth_type;
	__u16 proto;

	cur_init(&cur);
	/* this is VERY IMPORTANT! the cur_init() unset all the cursor offsets.
	 * The first one to be used is the mhoff, so it needs to be set to 0.
	 */
	cur_reset_mac_header(&cur);

	eth_type = parse_ethhdr(ctx, &cur, &eth);
	if (unlikely(!eth || eth_type < 0)) {
		pr_debug("cannot parse the ethernet header, abort");
		record_event(E_ETH_ERR);

		return XDP_ABORTED;
	}

	/* set the network header */
	cur_reset_network_header(&cur);

	proto = bpf_htons(eth_type);
	switch (proto) {
	case ETH_P_IPV6:
		record_event(E_IPV6_PROTO);
		return __raw_handle_ipv6(ctx, &cur);
	case ETH_P_IP:
		/* fallthrough */
	default:
		record_event(E_L3_UNK_PROTO);
		pr_debug("passthrough for proto=%x", bpf_htons(eth_type));
		break;
	}

	/* default policy allows any unrecognized packet... */
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
