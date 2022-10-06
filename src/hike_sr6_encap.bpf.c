// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#define HIKE_PROG_NAME sr6_encap

#ifndef HIKE_PRINT_LEVEL
#define HIKE_PRINT_LEVEL HIKE_PRINT_LEVEL_DEBUG
#endif

#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/seg6.h>
#include <linux/udp.h>
#include <linux/errno.h>

/* HIKe Chain IDs and XDP eBPF/HIKe programs IDs */
#include "minimal.h"

#include "parse_helpers.h"
#include "hike_vm.h"

#define SR6_OUTER_HOPLIMIT_VALUE	64
#define SR6_ENCAP_POLICY_MAP_SIZE	128

/* ========================== DO NOT EDIT BELOW =============================*/

#ifndef HIKE_PROG_NAME
#error "Please define the HIKE_PROG_NAME macro before using this program"
#endif

/* declare the proto of the function representing the program */
HIKE_VM_PROG_PROTO(HIKE_PROG_NAME);

#define SR6_ENCAP_SRC_ADDR_INDEX	0
#define SR6_SRC_TUN_MAP_SIZE		1

/* hashtable map containing the binding between incoming net device and tunnel
 * source address to be set in the outer IPv6 header, once the encap has been
 * carried out.
 */
#define SRV6_SRC_TUN_MAP sr6_src_tun

bpf_map(SRV6_SRC_TUN_MAP, HASH, __u32, struct in6_addr, SR6_SRC_TUN_MAP_SIZE);
EXPORT_HIKE_PROG_MAP(HIKE_PROG_NAME, SRV6_SRC_TUN_MAP);

/* just for convenience */
#define hdr_ptr(ctx, off, size) \
	cur_header_pointer(ctx, NULL, off, size)

#define get_ethhdr(ctx, cur) \
	((struct ethhdr *)hdr_ptr(ctx, (cur)->mhoff, sizeof(struct ethhdr)))

#define get_ipv6hdr(ctx, cur) \
	((struct ipv6hdr *)hdr_ptr(ctx, (cur)->nhoff, sizeof(struct ipv6hdr)))

#define get_ipv4hdr(ctx, cur) \
	((struct iphdr *)hdr_ptr(ctx, (cur)->nhoff, sizeof(struct iphdr)))

#define cur_xdp_expand_head(ctx, cur, len) \
	cur_xdp_adjust_head(ctx, cur, -(len))

#define __DEFINE_SR6_HDR_SIDLIST(N) \
	EVAL_CAT_3(ipv6_sr_hdr_sidlist, _, N)

#define DEFINE_SR6_HDR_SIDLIST(N)			\
struct  __DEFINE_SR6_HDR_SIDLIST(N) {			\
	struct ipv6_sr_hdr srh;				\
	struct in6_addr segs[(N)];			\
}

#define DECLARE_SR6_HDR_SIDLIST(NAME, NSID)		\
	struct __DEFINE_SR6_HDR_SIDLIST(NSID) NAME

#define __BPF_MAP_SR6_HDR_SIDLIST(N) \
	EVAL_CAT_3(sr6_encap_policy, _, N)

#define BPF_MAP_SR6_HDR_SIDLIST(N)			\
	bpf_map(__BPF_MAP_SR6_HDR_SIDLIST(N),		\
		HASH,					\
		__u32,					\
		struct __DEFINE_SR6_HDR_SIDLIST(N),	\
		SR6_ENCAP_POLICY_MAP_SIZE)

#define DEFINE_MAP_SR6_HDR_SIDLIST(N)			\
	DEFINE_SR6_HDR_SIDLIST(N);			\
	BPF_MAP_SR6_HDR_SIDLIST(N);			\
	EXPORT_HIKE_PROG_MAP(HIKE_PROG_NAME,		\
			     __BPF_MAP_SR6_HDR_SIDLIST(N))

#define __DO_SRH_ENCAP_FUNC_NAME __do_srh_encap_policy

#define DO_SRH_ENCAP_SIDLIST(NSIDS) static __always_inline int 		\
EVAL_CAT_3(__DO_SRH_ENCAP_FUNC_NAME, _, NSIDS)(struct xdp_md *ctx,	\
					       struct hdr_cursor *cur,	\
					       __u32 *index,		\
					       __u8 proto)		\
{									\
	DECLARE_SR6_HDR_SIDLIST(*entry, NSIDS);				\
	DECLARE_SR6_HDR_SIDLIST(*psl, NSIDS);				\
	struct ipv6_sr_hdr *srh;					\
	struct ipv6hdr *ip6h;						\
	struct in6_addr *da;						\
									\
	entry = bpf_map_lookup_elem(&__BPF_MAP_SR6_HDR_SIDLIST(NSIDS),	\
				    index);				\
	if (unlikely(!entry))						\
		/* no SRv6 Policy is present at the given @index */	\
		return -ENOENT;						\
									\
	psl = (struct __DEFINE_SR6_HDR_SIDLIST(NSIDS) *)		\
			hdr_ptr(ctx, cur->thoff, sizeof(*psl));		\
	if (unlikely(!psl))						\
		return -EINVAL;						\
									\
	/* copy the whole SRH (8 bytes of the header + SID List).	\
	 * NOTE: the srh must be already filled by the user space.	\
	 */								\
	memcpy(psl, entry, sizeof(*psl));				\
									\
	srh = &psl->srh;						\
	srh->nexthdr = proto;						\
									\
	/* ============================================= */		\
	/* srh->hdrlen = ((8 + (NSIDS) * 16) >> 3) - 1;	 */		\
	/* srh->type = 4;				 */		\
	/* srh->segments_left = (NSIDS) - 1;		 */		\
	/* srh->first_segment = (NSIDS) - 1;		 */		\
	/* ============================================= */		\
									\
	ip6h = get_ipv6hdr(ctx, cur);					\
	if (unlikely(!ip6h))						\
		return -EINVAL;						\
									\
	/* use the macro NSIDS instead of the srh->first_segment,	\
	 * otherwise the verifier will complain about an invalid	\
	 * access to the packet.					\
	 */								\
	da = &psl->segs[(NSIDS) - 1];					\
	memcpy(&ip6h->daddr, da, sizeof(*da));				\
									\
	return 0;							\
}

#define REGISTER_ENCAP_SIDLIST(NSIDS)					\
	DEFINE_MAP_SR6_HDR_SIDLIST(NSIDS);				\
	DO_SRH_ENCAP_SIDLIST(NSIDS)

REGISTER_ENCAP_SIDLIST(1);
REGISTER_ENCAP_SIDLIST(2);
REGISTER_ENCAP_SIDLIST(3);
REGISTER_ENCAP_SIDLIST(4);
REGISTER_ENCAP_SIDLIST(5);
REGISTER_ENCAP_SIDLIST(6);
REGISTER_ENCAP_SIDLIST(7);
REGISTER_ENCAP_SIDLIST(8);

static __always_inline void show_pkt_info(const struct hdr_cursor *cur)
{
	hike_pr_debug("dataoff=%d", cur->dataoff);
	hike_pr_debug("mhoff=%d", cur->mhoff);
	hike_pr_debug("nhoff=%d", cur->nhoff);
	hike_pr_debug("thoff=%d", cur->thoff);
}

static __always_inline void
ip6_flow_hdr(struct ipv6hdr *hdr, unsigned int tclass, __be32 flowlabel)
{
	*(__be32 *)hdr = bpf_htonl(0x60000000 | (tclass << 20)) | flowlabel;
}

static __always_inline int
do_srh_encap(struct xdp_md *ctx, struct hdr_cursor *cur, __u16 nsids,
	     __u32 *index, __u8 proto)
{
	int rc;

#define __srh_encap_side_effect__(NSIDS)				\
	case (NSIDS):							\
		rc = EVAL_CAT_3(__DO_SRH_ENCAP_FUNC_NAME, _, NSIDS)	\
			(ctx, cur, index, proto);			\
		break;

	switch (nsids) {
	__srh_encap_side_effect__(1);
	__srh_encap_side_effect__(2);
	__srh_encap_side_effect__(3);
	__srh_encap_side_effect__(4);
	__srh_encap_side_effect__(5);
	__srh_encap_side_effect__(6);
	__srh_encap_side_effect__(7);
	__srh_encap_side_effect__(8);
	default:
		hike_pr_err("unsupported SID List of %d segs", nsids);
		return -EOPNOTSUPP;
	}

	/* NOTE: rc is set by __srh_encap_side_effect__X macro */
	if (unlikely(rc)) {
		hike_pr_err("cannot process the SRH properly");
		return rc;
	}

	return 0;
#undef __srh_encap_side_effect__
}

static __always_inline int set_tun_src(int ifindex, struct ipv6hdr *ip6h)
{
	struct in6_addr *sa;

	sa = bpf_map_lookup_elem(&SRV6_SRC_TUN_MAP, &ifindex);
	if (unlikely(!sa)) {
		hike_pr_err("cannot found src tunnel address for dev <%d>\n",
			    ifindex);
		return -ENODEV;
	}

	ip6h->saddr = *sa;

	return 0;
}

HIKE_PROG(HIKE_PROG_NAME)
{
	struct ethhdr *old_eth, *eth;
	struct hdr_cursor *cur;
	struct pkt_info *info;
	struct ipv6hdr *ip6h;
	__u16 payload_length;
	unsigned int maclen;
	struct iphdr *ip4h;
	__u16 protocol;
	__u8 nexthdr;
	int tot_len;
	__u32 index;
	__u8 nsegs;
	int rc;

	/* retrieve input parameters */
	nsegs = HVM_REG_TO_u8(HVM_ARG2);
	index = HVM_REG_TO_u32(HVM_ARG3);

	hike_pr_debug(">>> ID=<0x%llx> NSIDS=<%d>, INDEX=<%d> <<<",
		      HVM_ARG1, nsegs, index);

	info = hike_pcpu_shmem();
	if (unlikely(!info)) {
		hike_pr_emerg("cannot access the HIKe VM pkt_info data");
		rc = -ENOMEM;
		goto abort;
	}

	cur = pkt_info_cur(info);
	/* no need to check for the returned pointer */

	hike_pr_debug("packet cursor snapshot on entry");
	show_pkt_info(cur);

	maclen = cur->nhoff - cur->mhoff;
	if (unlikely(maclen != sizeof(struct ethhdr))) {
		hike_pr_crit("VLAN not yet supported in ethernet header");
		rc = -EOPNOTSUPP;
		goto abort;
	}

	/* Very likely the cur->dataoff points after the IPv6 header, assuming
	 * that the IPv6 has been already processed.
	 * Reset the data offset to the the network offset which MUST point to
	 * the beginning of the IPv6 header, e.g. soon after the L2 layer.
	 */
	cur->dataoff = cur->nhoff;

	tot_len = sizeof(struct ipv6hdr) + sizeof(struct ipv6_sr_hdr) +
		  (nsegs << 4);

	/* expand the xdp frame */
	rc = cur_xdp_expand_head(ctx, cur, tot_len);
	if (unlikely(rc)) {
		hike_pr_err("cannot expand the xdp frame correctly");
		goto abort;
	}

	old_eth = get_ethhdr(ctx, cur);
	if (unlikely(!old_eth)) {
eth_err:
		rc = -EINVAL;
		hike_pr_err("cannot access to ethernet header");
		goto abort;
	}

	protocol = bpf_ntohs(old_eth->h_proto);
	switch (protocol) {
	case ETH_P_IP:
		nexthdr = IPPROTO_IP;

		ip4h = get_ipv4hdr(ctx, cur);
		if (unlikely(!ip4h)) {
			rc = -EINVAL;
			hike_pr_err("cannot access to IPv4 header");
			goto abort;
		}

		payload_length = bpf_ntohs(ip4h->tot_len);
		break;
	case ETH_P_IPV6:
		nexthdr = IPPROTO_IPV6;

		ip6h = get_ipv6hdr(ctx, cur);
		if (unlikely(!ip6h)) {
ip6_err:
			rc = -EINVAL;
			hike_pr_err("cannot access to IPv6 header");
			goto abort;
		}

		payload_length = bpf_ntohs(ip6h->payload_len);
		break;
	default:
		rc = -EOPNOTSUPP;
		hike_pr_err("unsupported protocol <%x>", protocol);
		goto abort;
	}

	/* set the cur->dataoff to the beginning of the frame */
	__push(cur, tot_len + sizeof(*old_eth));
	cur_reset_mac_header(cur);

	eth = get_ethhdr(ctx, cur);
	if (unlikely(!eth))
		goto eth_err;

	/* the two headers do not overlap with each other */
	memcpy(eth, old_eth, sizeof(*eth));
	eth->h_proto = bpf_htons(ETH_P_IPV6);

	__pull(cur, sizeof(*eth));
	cur_reset_network_header(cur);

	ip6h = get_ipv6hdr(ctx, cur);
	if (unlikely(!ip6h))
		goto ip6_err;

	ip6_flow_hdr(ip6h, 0, 0);
	ip6h->hop_limit = SR6_OUTER_HOPLIMIT_VALUE;
	ip6h->nexthdr = IPPROTO_ROUTING;

	payload_length += tot_len;
	ip6h->payload_len = bpf_htons(payload_length);

	/* transport header points to the beginning of the SRH.
	 * NOTE: dataoff poitns to the outer IPv6 header.
	 */
	cur->thoff = cur->nhoff + sizeof(struct ipv6hdr);

	/* apply the encap considering the SRv6 Policies made of @nsegs and
	 * identified by @index.
	 */
	rc = do_srh_encap(ctx, cur, nsegs, &index, nexthdr);
	if (unlikely(rc)) {
		if (likely(rc == -ENOENT)) {
			hike_pr_debug("SRv6 policy not found");
			goto out;
		}

		goto abort;
	}

	/* set the source tunnel address in the outer IPv6 header.
	 * NOTE: we use an unique tunnel source address for the whole netns.
	 */
	rc = set_tun_src(SR6_ENCAP_SRC_ADDR_INDEX, ip6h);
	if (unlikely(rc))
		goto abort;

	rc = 0;
out:
	return HVM_PROG_RET(rc, HIKE_XDP_VM);

abort:
	return HVM_PROG_RET(rc, XDP_ABORTED);
}
EXPORT_HIKE_PROG_3(HIKE_PROG_NAME, __u8, nsids, __u32, index);

/* Note: maps have already been exported above, see REGISTER_ENCAP_SIDLIST */

char LICENSE[] SEC("license") = "Dual BSD/GPL";
