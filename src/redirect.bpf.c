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

/* Redirect frame to a given ifindex 
 *
 * input:
 *  - REG2: interface index
 *
 * output: XDP_REDIRECT in case of success, XDP_ABORTED in case of error.
 */
HIKE_PROG(redirect)
{
	const __u32 ifindex = _I_REG(2);
	
	DEBUG_PRINT("HIKe Prog: redirect_any REG_1=0x%llx, REG_2=0x%llx",
		    _I_REG(1), ifindex);

	return bpf_redirect(ifindex, 0);
}
EXPORT_HIKE_PROG(redirect);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
