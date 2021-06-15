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

/* Loader program is a plain eBPF XDP program meant for invoking an HIKe Chain.
 * For the moment, the chain ID is harcoded.
 */
__section("hike_loader")
int __xdp_hike_loader(struct xdp_md *ctx)
{
	const __u32 chain_id = HIKE_CHAIN_FOO_ID;
	int rc;

	bpf_printk(">>> HIKe VM Chain Boostrap, chain_ID=0x%x", chain_id);

	rc = hike_chain_boostrap(ctx, chain_id);

	bpf_printk(">>> HIKe VM Chain Boostrap, chain ID=0x%x returned=%d",
		   chain_id, rc);

	return XDP_ABORTED;
}

__section("xdp_pass")
int xdp_pass_prog(struct xdp_md *ctx)
{
	return XDP_PASS;
}

/* ~~~~~~~~~~~~~~~~~~~~~ XDP eBPF/HIKe programs ~~~~~~~~~~~~~~~~~~~~ */

HIKE_PROG(allow_any)
{
	DEBUG_PRINT("HIKe Prog: allow_any REG_1=0x%llx, REG_2=0x%llx",
		    _I_REG(1), _I_REG(2));

	return XDP_PASS;
}
EXPORT_HIKE_PROG(allow_any);

HIKE_PROG(drop_any)
{
	DEBUG_PRINT("HIKe Prog: drop_any REG_1=0x%llx, REG_2=0x%llx",
		    _I_REG(1), _I_REG(2));

	return XDP_DROP;
}
EXPORT_HIKE_PROG(drop_any);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
