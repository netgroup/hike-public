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

__section("hike_tlcl_loader")
int __xdp_hike_tlcl_loader(struct xdp_md *ctx)
{
	const __u32 chain_id = HIKE_CHAIN_DUMMY_TLCL_ID;
	int rc;

	DEBUG_PRINT(">>> HIKe VM Chain Boostrap, chain_ID=0x%x", chain_id);

	rc = hike_chain_boostrap(ctx, chain_id);

	DEBUG_PRINT(">>> HIKe VM Chain Boostrap, chain ID=0x%x returned=%d",
		    chain_id, rc);

	return XDP_ABORTED;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
