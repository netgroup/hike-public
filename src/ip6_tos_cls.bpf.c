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
#include "parse_helpers.h"

#define HIKE_TOS_CLASS_MAP_SIZE		256
bpf_map(map_tos_cls, PERCPU_HASH, __u32, __u64, HIKE_TOS_CLASS_MAP_SIZE);

/* per-CPU IPv6 TOS counter and classifier.
 *
 * Preconditions:
 *  - this program expects to parse the IPv6 packet starting from the network
 *    header offset. This value is retrieved from the struct pkt_info contained
 *    into the HIKe per-cpu shared memory.
 *
 * input:
 *  - REG1:	HIKe Program ID
 *
 * output:
 *  - REG0:	the total number of packets which have been classified
 *  		considering a given TOS.
 */

HIKE_PROG(ipv6_tos_cls)
{
	struct pkt_info *info = hike_pcpu_shmem();
	struct hdr_cursor *cur;
	struct ipv6hdr *hdr;
	__u64 *cnt, val;
	__u32 tos;

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

	tos = ipv6_get_dsfield(hdr) & 0xff;

	cnt = bpf_map_lookup_elem(&map_tos_cls, &tos);
	if (cnt) {
		/* element is found */
		*cnt += 1;
		goto out;
	}

	val = 1;
	bpf_map_update_elem(&map_tos_cls, &tos, &val, BPF_NOEXIST);

out:
	_I_REG(0) = tos;
	return HIKE_XDP_VM;

drop:
	return XDP_ABORTED;
}
EXPORT_HIKE_PROG(ipv6_tos_cls);
EXPORT_HIKE_PROG_MAP(ipv6_tos_cls, map_tos_cls);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
