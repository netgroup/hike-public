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

/* bpf_map() macro is shipped within the HIKe VM source code; however, we are
 * not using any HIKe VM feature here.
 */

/* store the state of the loop variable between tail calls */
bpf_map(raw_tlcl_status_map, PERCPU_ARRAY, __u32, __u32, 1);
bpf_map(raw_tlcl_jmp_map, PROG_ARRAY, __u32, __u32, 8);
bpf_map(raw_tlcl_l2xcon_map, ARRAY, __u32, __u32, 8);

static __always_inline __u32 *get_loop_variable(void)
{
	const __u32 key = 0;

	return  bpf_map_lookup_elem(&raw_tlcl_status_map, &key);
}

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
	__u32 prog_id = RAW_TLCL_EBPF_DO_STUFF;
	__u32 *i = get_loop_variable();
	int rc;

	DEBUG_PRINT(">>> __xdp_raw_tlcl_loader invoked");

	if (!i)
		goto drop;

	/* init part */
	/* TODO: add some processing load here to emulate the insns copy */
	*i = 0;

	rc = raw_tlcl_jmp_check_limit(ctx, i, TLCL_MAX_DEPTH, prog_id);
	if (!rc) {
		DEBUG_PRINT(">>> __xdp_raw_tlcl_do_stuff loop end, exit loop var=%d",
			    *i);

		bpf_tail_call(ctx, &raw_tlcl_jmp_map, RAW_TLCL_EBPF_L2XCON);

		bpf_printk(">>> __xdp_raw_tlcl_do_stuff fallthrough, drop");
		goto drop;
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
	__u32 prog_id = RAW_TLCL_EBPF_DO_STUFF;
	__u32 *i = get_loop_variable();
	int rc;

	if (!i) {
		bpf_printk(">>> __xdp_raw_tlcl_do_stuff cannot access to loop var");
		goto drop;
	}

	DEBUG_PRINT(">>> __xdp_raw_tlcl_do_stuff loop var=%d", *i);

	rc = raw_tlcl_jmp_check_limit(ctx, i, TLCL_MAX_DEPTH, prog_id);
	if (!rc) {
		DEBUG_PRINT(">>> __xdp_raw_tlcl_do_stuff loop end, exit loop var=%d",
			    *i);

		bpf_tail_call(ctx, &raw_tlcl_jmp_map, RAW_TLCL_EBPF_L2XCON);

		bpf_printk(">>> __xdp_raw_tlcl_do_stuff fallthrough, drop");
		goto drop;
	}

	/* in this example we treat the fallthrough as a failure */
	bpf_printk(">>> __xdp_raw_tlcl_do_stuff tailcall fallthrough");
drop:
	return XDP_ABORTED;
}

__section("raw_tlcl_l2xcon")
int __xdp_raw_tlcl_l2xcon(struct xdp_md *ctx)
{
	const __u32 iif = ctx->ingress_ifindex;
	__u32 *oif;

	oif = bpf_map_lookup_elem(&raw_tlcl_l2xcon_map, &iif);
	if (!oif) {
		bpf_printk(">>> __xdp_raw_tlcl_l2xcon iif=%d, invalid oif",
			   iif);
		return XDP_DROP;
	}

	DEBUG_PRINT(">>> __xdp_raw_tlcl_l2xcon cross-connecting iif=%d, oif=%d",
		    iif, *oif);

	return bpf_redirect(*oif, 0);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

