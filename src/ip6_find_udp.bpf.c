// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#define HIKE_PROG_NAME	ipv6_find_udp

#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <linux/errno.h>

#include <linux/udp.h>

/* HIKe Chain IDs and XDP eBPF/HIKe programs IDs */
#include "minimal.h"

#include "parse_helpers.h"
#include "hike_vm.h"

/* HIKe eBPF Program
 *
 * The program allows the user to find out if the L4 contains the UDP header.
 * In case of success, the packet metadata info (hdr_cursor) is updated so that
 * the cur->dataoff points to the beginning of the UDP header.
 *
 * Beware that the hdr_cursor may be updated also in case that an error occurs
 * during the packet processing.
 *
 * input:
 *  - ARG1:	HIKe Progam ID.
 *
 *  output:
 *   - HVM_RET:	ret code (rc) operation
 *
 *  The returned code (rc for short) of ipv6_find_udp HIKe eBPF Program can
 *  be either:
 *   o) -ENOENT, if the UDP header is not found;
 *   o) < 0, in case an error occurred during the parsing process;
 *   o) IPPROTO_UDP (aka 17) if, the UDP header is found.
 *
 *  In case of error, the program *does* not return the control to the HIKe
 *  VM and it aborts the packet processing operation (i.e.: drops the packet).
 *  Otherwise, the flow control is returned back to the HIKe VM which
 *  continues to execute the processing in the calling chain.
 */
HIKE_PROG(HIKE_PROG_NAME)
{
	struct pkt_info *info = hike_pcpu_shmem();
	struct hdr_cursor *cur;
	struct ipv6hdr *ip6h;
	bool found = false;
	bool final = false;
	__u8 nexthdr;
	int start;
	int len;
	int rc;

	if (unlikely(!info))
		goto error;

	/* take the reference to the cursor object which has been saved into
	 * the HIKe per-cpu shared memory
	 */
	cur = pkt_info_cur(info);
	/* no need for checking cur != NULL here */

	ip6h = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff,
						    sizeof(*ip6h));
	if (unlikely(!ip6h))
		goto error;

	nexthdr = ip6h->nexthdr;
check_udp:
	/* data and thoff point after the IPv6 header */
	found = (nexthdr == IPPROTO_UDP);
	if (found) {
		if (!cur_may_pull(ctx, cur, sizeof(struct udphdr)))
			goto error;

		rc = nexthdr;
		goto out;
	}

	/* UDP not found after IPv6 */
	if (final)
		goto not_found;

	/* we assume that thoff is set after IPv6 and at the beginning of the 
	 * first header after the base IPv6 header
	 * this program does not change thoff
	 */
	start = cur->thoff;
	rc = ipv6_skip_exthdr(ctx, cur, &start, &nexthdr);
	if (unlikely(rc < 0))
		goto error;

	if (nexthdr != NEXTHDR_IPV6)
		goto not_found;

	len = start - cur->thoff;
	__pull(cur, len);

	ip6h = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->dataoff,
						    sizeof(*ip6h));
	if (unlikely(!ip6h))
		goto error;

	__pull(cur, sizeof(*ip6h));
	/* cur->dataoff now points just after the IPv6 header */
	nexthdr = ip6h->nexthdr;

	final = true;
	goto check_udp;

not_found:
	rc = -ENOENT;
out:
	/* return code for the invoking HIKe Chain */
	HVM_RET = rc;
	/* return code for the HIKe VM */
	return HIKE_XDP_VM;

error:
	return XDP_ABORTED;
}
EXPORT_HIKE_PROG(HIKE_PROG_NAME);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
