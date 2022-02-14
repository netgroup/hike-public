// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#define HIKE_PROG_NAME sr6_inline_udp

#define HIKE_PRINT_LEVEL	7 /* DEBUG level is set by default */

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

#include "hike_string.h"

/* support up to 511 byte to be moved before the SRH inline during the popping
 * operation.
 * If this macro is not defined, we fallback on a simpler pop solution that
 * is only able to move mac header plus the IPv6 headers preceding SRH.
 */
#define SUPPORT_ANY_EXTHDR_BEFORE_SRH_POP

HIKE_PROG(HIKE_PROG_NAME)
{
#define BUF_LEN	16
	struct pkt_info *info = hike_pcpu_shmem();
	struct __shm_buff {
		char p[BUF_LEN];
	} *pshm;
#ifndef SUPPORT_ANY_EXTHDR_BEFORE_SRH_POP
	struct ethhdr *old, *new;
	struct ipv6hdr *new_ip6h;
#else
	unsigned char *to, *from;
#endif
	unsigned char *data_end;
	struct ipv6_sr_hdr *srh;
	struct hdr_cursor *cur;
	unsigned int shmem_off;
	int srh_len = -EINVAL;
	int srhoff = -EINVAL;
	struct ipv6hdr *ip6h;
	struct udphdr *udph;
	struct ipv6hdr *ph;
	int found = false;
	int srh_minlen;
	__u16 dest_port;
	__u16 src_port;
	__u16 udp_plen;
	__u16 udp_poff;
	__be16 udp_len;
	__sum16 check;
	__u16 ip6_len;
	char *keyword;
	int pull_len;
	int offset;
	__u64 *ok;
	char *p;
	int rc;
	int i;

	hike_pr_debug("ID=0x%llx cookie=<%d>", HVM_ARG1, HVM_ARG2);

	if (unlikely(!info)) {
		hike_pr_emerg("cannot access the HIKe VM pkt_info data");
		goto abort;
	}

	cur = pkt_info_cur(info);
	/* no need for checking cur != NULL right here */

	/* scratch area on shmem starts after the pkt_info area */
	shmem_off = sizeof(struct pkt_info);

	/* outer ipv6 */
	ip6h = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff,
						    sizeof(*ip6h));
	if (unlikely(!ip6h)) {
		hike_pr_err("cannot access the IPv6 header");
		goto abort;
	}

	hike_pr_debug("HIKe VM Packet info");
	hike_pr_debug("dataoff=%d", cur->dataoff);
	hike_pr_debug("mhoff=%d\n", cur->mhoff);
	hike_pr_debug("nhoff=%d", cur->nhoff);
	hike_pr_debug("thoff=%d", cur->thoff);

	offset = 0;
	rc = ipv6_find_hdr(ctx, cur, &offset, IPPROTO_UDP, NULL, NULL);
	if (unlikely(rc < 0)) {
		hike_pr_info("No UDP header found");
		goto out;
	}

	/* set the dataoff and transport header to the UDP layer */
	cur->dataoff = offset;
	cur_reset_transport_header(cur);

	pull_len = cur->dataoff - (cur->nhoff + sizeof(*ip6h));
	if (unlikely(pull_len < 0)) {
		hike_pr_err("pull length cannot be negative");
		goto abort;
	}

	hike_pr_debug("HIKe VM Packet info after found IPPROTO_UDP");
	hike_pr_debug("dataoff=%d", cur->dataoff);
	hike_pr_debug("mhoff=%d\n", cur->mhoff);
	hike_pr_debug("nhoff=%d", cur->nhoff);
	hike_pr_debug("thoff=%d", cur->thoff);
	hike_pr_debug("pull_len=%d", pull_len);

	udph = (struct udphdr *)cur_header_pointer(ctx, cur, cur->dataoff,
						   sizeof(*udph));
	if (unlikely(!udph)) {
		hike_pr_err("cannot access the UDP header");
		goto abort;
	}

	src_port = bpf_ntohs(udph->source);
	dest_port = bpf_ntohs(udph->dest);
	udp_len = bpf_ntohs(udph->len);
	hike_pr_info("udp src port=%d", src_port);
	hike_pr_info("udp dest port=%d", dest_port);
	hike_pr_info("udp len=%d", udp_len);

	ph = ip6h;
	if (unlikely(!ph)) {
		hike_pr_crit("pseudo-header MUST NOT be null... weird...");
		goto abort;
	}

	/* before evaluating the checksum, we need to check if we have, at
	 * least, one ext header.
	 * If so, we have to handle it and adjust the IPv6 pseudo-header.
	 */
	if (ph->nexthdr == IPPROTO_UDP)
		goto eval_checksum;

	hike_pr_info("IPv6 Ext. HDRs present, build new IPv6 pseudo-header");

	/* TODO: such kind of checks should be done in separate functions...
	 * For the moment we only support:
	 *
	 *     +-----------------------------------+
	 *     | IPv6 | Ext HDR(s) | UDP | Payload |
	 *     +-----------------------------------+
	 */

	/* let's allocate the IPv6 hdr bytes on the shmem rather than hogging
	 * the stack... :-)
	 */
	ph = hike_pcpu_shmem_obj(shmem_off, struct ipv6hdr);
	if (unlikely(!ph)) {
		hike_pr_crit("error during access to shmem");
		goto abort;
	}

	/* this emulates a kind of allocation in the per-CPU shmem */
	shmem_off += sizeof(*ph);

	memcpy(ph, ip6h, sizeof(*ph));
	ph->nexthdr = IPPROTO_UDP;

	/* since UDP does not have any length field, we need to take the IPv6
	 * payload len subtracting the length of proto(s) which are in between
	 * IPv6 and UDP.
	 */
	ip6_len = bpf_ntohs(ph->payload_len);
	ip6_len -= pull_len;
	ph->payload_len = bpf_htons(ip6_len);

	hike_pr_info("IPv6 pseudo-header proto=%d", ph->nexthdr);
	hike_pr_info("IPv6 pseudo-header len=%d", ip6_len);

	/* we need to take the last segment and copy it into the IPv6 DA */
	srhoff = cur->nhoff;
	rc = ipv6_find_hdr(ctx, cur, &srhoff, NEXTHDR_ROUTING, NULL, NULL);
	if (unlikely(rc < 0)) {
		hike_pr_err("cannot locate SRH");
		goto abort;
	}

	/* we are looking for an SRH with at least one sid. The first sid in
	 * the sidlist is the last one ;-)
	 */
	srh_minlen = sizeof(*srh) + sizeof(srh->segments[0]);
	srh = (struct ipv6_sr_hdr *)cur_header_pointer(ctx, cur, srhoff,
						       srh_minlen);
	if (unlikely(!srh)) {
		hike_pr_err("SRH must contain one SID at least");
		goto abort;
	}

	srh_len = (srh->hdrlen + 1) << 3;
	if (unlikely(srh_minlen > srh_len)) {
		hike_pr_err("invalid SRH length");
		goto abort;
	}

	/* first sid is the last one (in traverse order) */
	memcpy(&ph->daddr, &srh->segments[0], sizeof(ph->daddr));

eval_checksum:
	rc = ipv6_udp_checksum(ctx, ph, udph, &check);
	if (unlikely(rc)) {
		hike_pr_err("checksum error=%d", rc);
		goto abort;
	}

	hike_pr_info("pkt UDP checksum=0x%x, eval UDP checksum=0x%x",
		     bpf_ntohs(udph->check), bpf_ntohs(check));

	if (unlikely(udp_len < sizeof(*udph)))
		goto abort;

	if (udp_len == sizeof(*udph))
		/* no payload for this UDP packet */
		goto out;

	/* reserve some space for storing the string to be searched */
	pshm = hike_pcpu_shmem_obj(shmem_off, struct __shm_buff);
	if (unlikely(!pshm)) {
		hike_pr_crit("error during access to shmem");
		goto abort;
	}

	shmem_off += sizeof(*pshm);

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
	if (unlikely(!p)) {
		/* since we already check for the udp_len, if we cannot access
		 * the first byte of the payload, something very weird is just
		 * happened...
		 */
		hike_pr_crit("cannot access to UDP payload");
		goto abort;
	}

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

	ok = hike_pcpu_shmem_obj(shmem_off, __u64);
	if (unlikely(!ok)) {
		hike_pr_crit("error during access to shmem");
		goto abort;
	}

	shmem_off += sizeof(ok);

	hike_pr_debug("shmem_off=%d", shmem_off);

	/* string found event stored into the shmem */
	*ok = 1;
	found = (*ok == 1);

	hike_pr_notice(">>> keyword '%s' found <<<", keyword);

out:
	/* We are about to pop the inline SRH, if any.
	 * TODO: we have to make a separate function or program to do that!
	 */
	if (srh_len < 0)
		goto out2;

#ifndef SUPPORT_ANY_EXTHDR_BEFORE_SRH_POP
	/* Supported for the moment only the following layout:
	 *
	 *  +----------------------------------+
	 *  | eth | IPv6 | SRH | UDP | payload |
	 *  +----------------------------------+
	 */
	old = (struct ethhdr *)cur_header_pointer(ctx, cur, cur->mhoff,
						  sizeof(*old));
	new = (struct ethhdr *)cur_header_pointer(ctx, cur, cur->mhoff +
						  srh_len,
						  sizeof(*new));
	if (unlikely(!new || !old))
		goto abort;

	/* we are moving the mac header */
	memmove(new, old, sizeof(*new));

	new_ip6h = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff +
							srh_len,
							sizeof(*new_ip6h));
	if (unlikely(!new_ip6h))
		goto abort;

	/* we are moving the IPv6 header.
	 * NB: we are copying the pseudo-header since we have just fixed the
	 * DA, payload_len and proto.
	 */
	memmove(new_ip6h, ph, sizeof(*new_ip6h));

	rc = bpf_xdp_adjust_head(ctx, srh_len);
	if (unlikely(rc < 0)) {
		hike_pr_err("cannot adjust the xdp frame sizeo of %d",
			    -srh_len);
		goto abort;
	}

	hike_pr_info("SRH inline popped out");

	/* TODO: re-evaluate the pkt_info pointers as we do when the
	 * SUPPORT_ANY_EXTHDR_BEFORE_SRH_POP is turned on.
	 */
#else
	/* Supported for the moment only the following layout:
	 *
	 *  +----------------------------------------------------------+
	 *  | eth | IPv6 | Ext. HDRs | SRH | Ext. HDRs | UDP | payload |
	 *  +----------------------------------------------------------+
	 *   ^^^^^^^^^^^^^^^^^^^^^^^  ^^^^^
	 *               \              \___ will be popped out
	 *               |
	 *               |___ up to 511 bytes can precede the SRH to be popped
	 */

	ip6h->payload_len = ph->payload_len;
	ip6h->nexthdr = ph->nexthdr;
	ip6h->daddr = ph->daddr;

	/* let's take raw packet poitners */
	to = (unsigned char *)(xdp_md_head(ctx) + srh_len);
	from = (unsigned char *)xdp_md_head(ctx);
	/* XXX: even if data_end was loaded with the xdp_md_tail value, the
	 * verifier is not able to verify the program; we need to load the
	 * 'tail' address of the packet once again.
	 * This seems to be a verifier issue...
	 */
	data_end = (unsigned char *)xdp_md_tail(ctx);

	rc = hike_memmove(to, from, srh_len, data_end);
	if (unlikely(rc < 0)) {
		hike_pr_err("cannot move data into the packet");
		goto abort;
	}

	/* thoff and dataoff are still pointing to the UDP layer; since we have
	 * to remove the SRH, the nhoff as well as the mhoff must be reset.
	 */
	cur_mac_header_unset(cur);
	cur_network_header_unset(cur);

	rc = cur_xdp_adjust_head(ctx, cur, srh_len);
	if (unlikely(rc < 0)) {
		hike_pr_err("cannot adjust the xdp frame sizeo of %d",
			    -srh_len);
		goto abort;
	}

	hike_pr_info("SRH inline popped out (Generic SRH pop supported)");

	hike_pr_debug("HIKe VM Packet info after cur_xdp_adjust_header");
	hike_pr_debug("dataoff=%d", cur->dataoff);
	hike_pr_debug("mhoff=%d\n", cur->mhoff);
	hike_pr_debug("nhoff=%d", cur->nhoff);
	hike_pr_debug("thoff=%d", cur->thoff);

	/* we should set the {mac, network} offsets valid values.
	 *
	 * Every time we mangle the packet, we should always keep the hdr
	 * cursor offsets in a valid state. In this example, we are going to
	 * parse the mac header and the network header once again (the headers
	 * that have been moved after the SRH pop operations).
	 *
	 * Obviously, parsing such headers ends in a processing overhead :-)
	 */
	cur->dataoff = 0;
	cur_reset_mac_header(cur);

	rc = parse_ethhdr(ctx, cur, NULL);
	if (unlikely(rc != bpf_ntohs(ETH_P_IPV6))) {
		hike_pr_err("expected IPv6 proto in mac header after SRH pop");
		goto abort;
	}

	cur_reset_network_header(cur);

	rc = parse_ip6hdr(ctx, cur, NULL);
	if (unlikely(rc < 0)) {
		hike_pr_err("cannot parse IPv6 Header after SRH pop");
		goto abort;
	}

	/* after having parsed the IPv6 header, the thoff and the dataoff must
	 * be same.
	 */

	hike_pr_debug("HIKe VM Packet info after re-adjusting hdr cursor");
	hike_pr_debug("dataoff=%d", cur->dataoff);
	hike_pr_debug("mhoff=%d\n", cur->mhoff);
	hike_pr_debug("nhoff=%d", cur->nhoff);
	hike_pr_debug("thoff=%d", cur->thoff);
#endif

out2:
	HVM_RET = found;
	return HIKE_XDP_VM;

abort:
	hike_pr_err("abort; packet is going to be dropped");
	return XDP_ABORTED;
#undef BUF_LEN
}
EXPORT_HIKE_PROG_2(HIKE_PROG_NAME, __u64, cookie);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
