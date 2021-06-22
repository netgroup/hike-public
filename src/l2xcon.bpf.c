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

#define HIKE_EBPF_PROG_L2XCON_IFMAX	8

bpf_map(l2xcon_map, ARRAY, __u32, __u32, HIKE_EBPF_PROG_L2XCON_IFMAX);

/* Cross-connect two interfaces. Packet's incoming intefrace is used to lookup
 * the egress interface and then, the packet is forwarded untouched.
 *
 * output: XDP_REDIRECT in case of success, XDP_ABORTED in case of error.
 */
HIKE_PROG(l2xcon)
{
	const __u32 iif = ctx->ingress_ifindex;
	__u32 *oif;

	DEBUG_PRINT("HIKe Prog: l2xcon REG_1=0x%llx, iif=%d", _I_REG(1), iif);

	oif = bpf_map_lookup_elem(&l2xcon_map, &iif);
	if (!oif) {
		DEBUG_PRINT("HIKe Prog: l2xcon invalid oif");
		return XDP_ABORTED;
	}

	DEBUG_PRINT("HIKe Prog: l2xcon cros-connectiong iif=%d, oif=%d",
		    iif, *oif);

	return bpf_redirect(*oif, 0);
}
EXPORT_HIKE_PROG(l2xcon);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
