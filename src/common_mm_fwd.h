
#ifndef _COMMON_MM_FWD_H
#define _COMMON_MM_FWD_H

#include <linux/bpf.h>
#include <linux/btf.h>
#include <bpf/bpf_helpers.h>

#include "map.h"
#include "parse_helpers.h"

struct mm_fwd_pkt {
	__u64 ipv6_marked;
};

#define HIKE_MM_FWD_MAP_SIZE		1
bpf_map(mm_fwd_map, PERCPU_ARRAY, __u32, struct mm_fwd_pkt,
	HIKE_MM_FWD_MAP_SIZE);

static __always_inline int ipv6_mm_inc_cnt(void)
{
	struct mm_fwd_pkt *cnt;
	/* only ipv6 is supported which corresponds to the only entry in
	 * the PCPU_ARRAY.
	 */
	const __u32 key = 0;

	cnt = bpf_map_lookup_elem(&mm_fwd_map, &key);
	if (likely(cnt)) {
		cnt->ipv6_marked +=  1;
		return 0;
	}

	return -ENOENT;
}

static __always_inline void ipv6_dscp_mark(struct ipv6hdr *hdr,
					   __u8 dscp_mask, __u8 dscp)
{
	ipv6_set_dsfield(hdr, dscp_mask, dscp);
}

#define HIKE_MM_FWD_LOWPRIO	0x01	/* Congestion Experienced YES */
#define HIKE_MM_FWD_DSCP_MASK	0x00	/* clear dscp */
static __always_inline void ipv6_lowprio_mark(struct ipv6hdr *hdr)
{
	ipv6_dscp_mark(hdr, HIKE_MM_FWD_DSCP_MASK, HIKE_MM_FWD_LOWPRIO);
}

#endif
