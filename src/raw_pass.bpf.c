// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include <linux/bpf.h>
#include <linux/btf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define __stringify(X)		#X
#define stringify(X)		__stringify(X)

#ifndef __section
#define __section(NAME)					\
	__attribute__((section(NAME), used))
#endif

#ifndef __section_tail
#define __section_tail(ID, KEY)				\
	__section(__stringify(ID) "/" __stringify(KEY))
#endif

__section("xdp_pass")
int xdp_pass_prog(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
