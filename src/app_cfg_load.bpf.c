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

#include "app_cfg.h"
#include "parse_helpers.h"

HIKE_PROG(app_cfg_load)
{
	__u32 key = _I_REG(2);
	__u32 *val;
	__s64 rc;

	val = bpf_map_lookup_elem(&map_app_cfg, &key);
	if (!val) {
		rc = -ENOENT;
		goto out;
	}

	rc = (__u64)((*val) & 0xffffffff);
out:
	_I_REG(0) = rc;
	return HIKE_XDP_VM;
}
EXPORT_HIKE_PROG(app_cfg_load);
EXPORT_HIKE_PROG_MAP(app_cfg_load, map_app_cfg);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
