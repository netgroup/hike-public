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

#define HIKE_TOS_CLASS_MAP_SIZE		64
bpf_map(trace_pass_pcpu_map, PERCPU_HASH, __u32, __u64,
	HIKE_TOS_CLASS_MAP_SIZE);

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

HIKE_PROG(trace_pass)
{
	const __u32 key = _I_REG(2);
	__u64 *value;
	__u64 tmp;

	value = bpf_map_lookup_elem(&trace_pass_pcpu_map, &key);
	if (likely(value)) {
		*value += 1;
		return XDP_PASS;
	}

	tmp = 1;
	bpf_map_update_elem(&trace_pass_pcpu_map, &key, &tmp, BPF_NOEXIST);

	return XDP_PASS;
}
EXPORT_HIKE_PROG(trace_pass);
EXPORT_HIKE_PROG_MAP(trace_pass, trace_pass_pcpu_map);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
