// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#define HIKE_PROG_NAME hike_verbose

#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <linux/udp.h>
#include <linux/errno.h>

/* HIKe Chain IDs and XDP eBPF/HIKe programs IDs */
#include "minimal.h"

#include "parse_helpers.h"
#include "hike_vm.h"

HIKE_PROG(HIKE_PROG_NAME)
{
	struct pkt_info *info = hike_pcpu_shmem();
	struct hdr_cursor *cur;
	struct udphdr *udph;
	__u16 dest;

	DEBUG_HKPRG_PRINT("ID=0x%llx cookie=<%d>", HVM_ARG1, HVM_ARG2);

	if (unlikely(!info))
		goto abort;

	cur = pkt_info_cur(info);
	/* no need for checking cur != NULL right here */

	DEBUG_HKPRG_PRINT("pkt-info");
	DEBUG_HKPRG_PRINT("dataoff=%d", cur->dataoff);
	DEBUG_HKPRG_PRINT("nhoff=%d", cur->nhoff);
	DEBUG_HKPRG_PRINT("thoff=%d", cur->thoff);

	udph = (struct udphdr *)cur_header_pointer(ctx, cur, cur->dataoff,
						   sizeof(*udph));
	if (unlikely(!udph))
		goto abort;

	dest = bpf_ntohs(udph->dest);

	DEBUG_HKPRG_PRINT("udp dest port=%d", dest);

	return HIKE_XDP_VM;

abort:
	DEBUG_HKPRG_PRINT("abort");
	return XDP_ABORTED;
}
EXPORT_HIKE_PROG(HIKE_PROG_NAME);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
