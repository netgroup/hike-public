// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#define HIKE_PROG_NAME	l2_redirect

#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <linux/errno.h>

/* HIKe Chain IDs and XDP eBPF/HIKe programs IDs */
//#include "minimal.h"

#include "hike_vm.h"

HIKE_PROG(HIKE_PROG_NAME)
{
	const __u32 oif = __to_u32(HVM_ARG2);

	DEBUG_HKPRG_PRINT("ARG1=0x%llx, ARG2=%d", HVM_ARG1, oif);

	if (unlikely(!oif)) {
		DEBUG_HKPRG_PRINT("invalid oif=%d", oif);
		goto drop;
	}

	DEBUG_HKPRG_PRINT("redirect to oif=%d", oif);

	return bpf_redirect(oif, 0);

drop:
	DEBUG_HKPRG_PRINT("drop packet");
	return XDP_DROP;
}
EXPORT_HIKE_PROG(HIKE_PROG_NAME);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
