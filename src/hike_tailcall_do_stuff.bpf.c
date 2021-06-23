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

HIKE_PROG(tlcl_do_stuff)
{
#if HIKE_DEBUG == 1
	__u32 i = _I_REG(2);

	DEBUG_PRINT("HIKe Prog: tlcl_do_stuff REG_2=0x%llx", i);
#endif

	/* do some stuff here... */

	/* give back the control to the HIKe VM */
	return HIKE_XDP_VM;
}
EXPORT_HIKE_PROG(tlcl_do_stuff);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
