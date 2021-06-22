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

#define TLCL_MAX_DEPTH	4

/* store the state of the loop variable between tail calls */
bpf_map(raw_tlcl_status_map, PERCPU_ARRAY, __u32, __u32, 1);
bpf_map(raw_tlcl_jmp_map, PROG_ARRAY, __u32, __u32, 8);

static __always_inline __u32 *get_loop_variable(void)
{
	const __u32 key = 0;

	return  bpf_map_lookup_elem(&raw_tlcl_status_map, &key);
}

#define RAW_TLCL_EBPF_PROGRAM_ID	1

static __always_inline int
raw_tlcl_jmp_check_limit(struct xdp_md *ctx, __u32 *loop_var, __u32 depth,
			 __u32 prog_id)
{
	if (*loop_var >= depth)
		return 0;

	++(*loop_var);

	bpf_tail_call(ctx, &raw_tlcl_jmp_map, prog_id);

	/* fallthrough */
	return -ENOENT;
}

__section("raw_tlcl_loader")
int __xdp_raw_tlcl_loader(struct xdp_md *ctx)
{
	__u32 prog_id = RAW_TLCL_EBPF_PROGRAM_ID;
	__u32 *i = get_loop_variable();
	int rc;

	if (!i)
		goto drop;

	/* init part */
	/* TODO: add some processing load here to emulate the insns copy */
	*i = 0;

	rc = raw_tlcl_jmp_check_limit(ctx, i, TLCL_MAX_DEPTH, prog_id);
	if (!rc) {
		DEBUG_PRINT(">>> __xdp_raw_tlcl_loader loop end, var=%d", *i);
		return XDP_PASS;
	}

	/* in this example we treat the fallthrough as a failure */
	bpf_printk(">>> __xdp_raw_tlcl_loader tailcall fallthrough");
	return XDP_ABORTED;

drop:
	bpf_printk(">>> __xdp_raw_tlcl_loader cannot access to loop var");
	return XDP_ABORTED;
}

/* it differs from raw_tlcl_loader because it does not go through the
 * initilization part.
 */
__section("raw_tlcl_do_stuff")
int __xdp_raw_tlcl_do_stuff(struct xdp_md *ctx)
{
	__u32 prog_id = RAW_TLCL_EBPF_PROGRAM_ID;
	__u32 *i = get_loop_variable();
	int rc;

	if (!i)
		goto drop;

	DEBUG_PRINT(">>> __xdp_raw_tlcl_do_stuff loop var=%d", *i);

	rc = raw_tlcl_jmp_check_limit(ctx, i, TLCL_MAX_DEPTH, prog_id);
	if (!rc) {
		DEBUG_PRINT(">>> __xdp_raw_tlcl_do_stuff loop end, exit loop var=%d",
			    *i);
		return XDP_PASS;
	}

	/* in this example we treat the fallthrough as a failure */
	bpf_printk(">>> __xdp_raw_tlcl_do_stuff tailcall fallthrough");
	return XDP_ABORTED;

drop:
	bpf_printk(">>> __xdp_raw_tlcl_do_stuff cannot access to loop var");
	return XDP_ABORTED;
}

#if 0
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
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";
