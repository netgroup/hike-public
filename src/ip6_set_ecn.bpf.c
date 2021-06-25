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

HIKE_PROG(ipv6_set_ecn)
{
	struct pkt_info *info = hike_pcpu_shmem();
	struct hdr_cursor *cur;
	struct ipv6hdr *hdr;

	if (unlikely(!info))
		goto drop;

	/* take the reference to the cursor object which has been saved into
	 * the HIKe per-cpu shared memory
	 */
	cur = pkt_info_cur(info);

	/* ctx is injected by the HIKe VM */
	hdr = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff,
						   sizeof(*hdr));
	if (unlikely(!hdr))
		goto drop;

	/* set the ecn bit */
	ipv6_dscp_mark(hdr, 0xfe, 1);

	return HIKE_XDP_VM;

drop:
	return XDP_ABORTED;
}
EXPORT_HIKE_PROG(ipv6_set_ecn);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
