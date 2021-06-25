// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <linux/errno.h>

/* HIKe Chain IDs and XDP eBPF/HIKe programs IDs */
#include "minimal.h"

#include "hike_vm.h"
#include "common_mm_fwd.h"

HIKE_PROG(ipv6_mm_fwd)
{
	struct pkt_info *info = hike_pcpu_shmem();
	struct hdr_cursor *cur;
	struct ipv6hdr *hdr;

	if (!info)
		goto drop;

	/* take the reference to the cursor object which has been saved into
	 * the HIKe per-cpu shared memory
	 */
	cur = pkt_info_cur(info);

	/* ctx is injected by the HIKe VM */
	hdr = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff,
						   sizeof(*hdr));
	if (!hdr)
		goto drop;

	/* count the packet */
	ipv6_mm_inc_cnt();

	/* mark the packet */
	ipv6_lowprio_mark(hdr);

	return XDP_PASS;

drop:
	return XDP_ABORTED;
}
EXPORT_HIKE_PROG(ipv6_mm_fwd);
EXPORT_HIKE_PROG_MAP(ipv6_mm_fwd, mm_fwd_map);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
