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

#define HIKE_PCPU_MON_COUNT_MAX		1024
bpf_map(map_pcpu_mon, PERCPU_HASH, __u32, __u64, HIKE_PCPU_MON_COUNT_MAX);

/* per-CPU Event Monitor HIKe Program
 *
 * input:
 * - REG1:	HIKe Program ID;
 * - REG2:	32-bit event key;
 * - REG3:	boolean;
 *   		If true, the program creates an event with zeroed counter
 *   		considering the given key ONLY if it such event does not
 *   		already exist in the event map.
 *		If false, the program attempts to step up the counter bound to
 *		the given key. In case the key does not exist, the program
 *		reports the error to the HIKe VM.
 * output:
 *  - REG0:	0 if success; < 0 if an error occurred.
 */
HIKE_PROG(pcpu_mon)
{
	bool force_add = !!_I_REG(3);
	__u32 key = _I_REG(2);
	int rc = -ENOENT;
	__u64 *value;
	__u64 tmp;

	value = bpf_map_lookup_elem(&map_pcpu_mon, &key);
	if (likely(value)) {
		*value += 1;
		rc = 0;
		goto out;
	}

	if (!force_add)
		goto out;

	tmp = 1;
	rc = bpf_map_update_elem(&map_pcpu_mon, &key, &tmp, BPF_NOEXIST);

out:
	_I_REG(0) = rc;
	return HIKE_XDP_VM;
}
EXPORT_HIKE_PROG(pcpu_mon);
EXPORT_HIKE_PROG_MAP(pcpu_mon, map_pcpu_mon);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
