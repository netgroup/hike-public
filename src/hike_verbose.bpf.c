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
#define BUF_LEN	16
	struct pkt_info *info = hike_pcpu_shmem();
	struct __shm_buff {
		char p[BUF_LEN];
	} *pshm;
	unsigned char *data_end;
	struct hdr_cursor *cur;
	struct ipv6hdr *ip6h;
	struct udphdr *udph;
	__u16 dest_port;
	__u16 src_port;
	__u16 udp_plen;
	__u16 udp_poff;
	__be16 udp_len;
	__sum16 check;
	char *keyword;
	__u64 *ok;
	char *p;
	int rc;
	int i;

	DEBUG_HKPRG_PRINT("ID=0x%llx cookie=<%d>", HVM_ARG1, HVM_ARG2);

	if (unlikely(!info))
		goto abort;

	cur = pkt_info_cur(info);
	/* no need for checking cur != NULL right here */

	ip6h = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff,
						    sizeof(*ip6h));
	if (unlikely(!ip6h))
		goto abort;

	DEBUG_HKPRG_PRINT("pkt-info");
	DEBUG_HKPRG_PRINT("dataoff=%d", cur->dataoff);
	DEBUG_HKPRG_PRINT("nhoff=%d", cur->nhoff);
	DEBUG_HKPRG_PRINT("thoff=%d", cur->thoff);

	udph = (struct udphdr *)cur_header_pointer(ctx, cur, cur->dataoff,
						   sizeof(*udph));
	if (unlikely(!udph))
		goto abort;

	src_port = bpf_ntohs(udph->source);
	dest_port = bpf_ntohs(udph->dest);
	udp_len = bpf_ntohs(udph->len);
	DEBUG_HKPRG_PRINT("udp src port=%d", src_port);
	DEBUG_HKPRG_PRINT("udp dest port=%d", dest_port);
	DEBUG_HKPRG_PRINT("udp len=%d", udp_len);

	rc = ipv6_udp_checksum(ctx, ip6h, udph, &check);
	if (unlikely(rc)) {
		DEBUG_HKPRG_PRINT("checksum error=%d", rc);
		goto abort;
	}

	DEBUG_HKPRG_PRINT("udp check=0x%x", bpf_ntohs(check));

	if (unlikely(udp_len < sizeof(*udph)))
		goto abort;

	if (udp_len == sizeof(*udph))
		/* no payload for this UDP packet */
		goto out;

	/* reserve some space for storing the string to be searched */
	pshm = hike_pcpu_shmem_obj(sizeof(struct pkt_info), struct __shm_buff);
	if (unlikely(!pshm))
		goto abort;

	/* set the string in the shmem, so we do not overload the stack.
	 * In this case, the keyword to be found is pretty small and then it
	 * can be placed into the stack, directly.
	 * Howerver, this exmaple shows a possible way for loading very long
	 * strings or huge data block without hogging the stack (<= 512 bytes).
	 */
	pshm->p[0] = 'q';
	pshm->p[1] = 'w';
	pshm->p[2] = 'e';
	pshm->p[3] = 'r';
	pshm->p[4] = 't';
	pshm->p[5] = 'y';
	pshm->p[6] = '\0';
	/* any kind of garbage at this point */
	pshm->p[7] = 'c';
	pshm->p[8] = 'o';
	pshm->p[9] = 'o';
	pshm->p[10] = 'l';

	keyword = &pshm->p[0];

	/* search the keyword (prefix) */

	/* p points to the beginning of the UDP payload */
	udp_poff = cur->dataoff + sizeof(*udph);
	p = (char *)cur_header_pointer(ctx, cur, udp_poff, sizeof(*p));
	if (unlikely(!p))
		/* since we already check for the udp_len, if we cannot access
		 * the first byte of the payload, something very weird is just
		 * happened...
		 */
		goto abort;

	udp_plen = udp_len - sizeof(*udph);
	data_end = xdp_md_tail(ctx);

	for (i = 0; i < BUF_LEN; ++i, ++p) {
		if (keyword[i] == '\0')
			/* we treat the '\0' as the empty string..., the empty
			 * string is always a prefix for any word to be
			 * searched for.
			 */
			break;

		if (i >= udp_plen || !__may_pull(p, sizeof(*p), data_end))
			goto out;

		if (*p != keyword[i])
			goto out;
	}

	ok = hike_pcpu_shmem_obj(sizeof(struct pkt_info) +
				 sizeof(struct __shm_buff), __u64);
	if (unlikely(!ok))
		goto abort;

	/* string found event stored into the shmem */
	*ok = 1;

	DEBUG_HKPRG_PRINT(">>> keyword '%s' found <<<", keyword);
out:
	return HIKE_XDP_VM;

abort:
	DEBUG_HKPRG_PRINT("abort");
	return XDP_ABORTED;
#undef BUF_LEN
}
EXPORT_HIKE_PROG_2(HIKE_PROG_NAME, __u64, cookie);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
