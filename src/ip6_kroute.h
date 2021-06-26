
#ifndef _IPV6_KROUTE_H
#define _IPV6_KROUTE_H

#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/errno.h>

#include "hdr_cursor.h"

#ifndef AF_INET
#define AF_INET			2
#endif

#ifndef AF_INET6
#define AF_INET6		10
#endif

#define __IPV6_FLOWINFO_MASK	bpf_htonl(0x0FFFFFFF)

#ifndef memset
#define memset(dest, val, n) __builtin_memset((dest), (val), (n))
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif

static __always_inline int
__ipv6_route(struct xdp_md *ctx, struct hdr_cursor *cur, __u32 flags)
{
	struct bpf_fib_lookup fib_params;
	struct in6_addr *saddr, *daddr;
	struct ipv6hdr *ip6h;
	struct ethhdr *eth;
	int action;
	int rc;

	memset((void *)&fib_params, 0, sizeof(fib_params));

	ip6h = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff,
						    sizeof(*ip6h));
	if (unlikely(!ip6h))
		goto error;

	if (ip6h->hop_limit <= 1)
		/* we let the kernel decide what to do in this situation */
		return XDP_PASS;

	saddr = (struct in6_addr *)fib_params.ipv6_src;
	daddr = (struct in6_addr *)fib_params.ipv6_dst;

	*saddr			= ip6h->saddr;
	*daddr			= ip6h->daddr;
	fib_params.family	= AF_INET6;
	fib_params.flowinfo	= *((__be32 *)ip6h) & __IPV6_FLOWINFO_MASK;
	fib_params.tot_len	= bpf_ntohs(ip6h->payload_len);
	fib_params.l4_protocol	= ip6h->nexthdr;
	fib_params.sport	= 0;
	fib_params.dport	= 0;
	fib_params.ifindex	= ctx->ingress_ifindex;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), flags);

	switch (rc) {
	case BPF_FIB_LKUP_RET_SUCCESS:
		/* lookup successful */

		/* decrease the hop-limit and prepare the ethernet layer
		 * for submitting the frame.
		 */
		ip6h->hop_limit--;

		eth = (struct ethhdr *)cur_header_pointer(ctx, cur, cur->mhoff,
							  sizeof(*eth));
		if (unlikely(!eth))
			goto error;

		/* TODO: to optimize ? */
		memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

		action = bpf_redirect(fib_params.ifindex, 0);

		break;

	case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
	case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
	case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
		action = XDP_DROP;
		break;

	case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
	case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
	case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
	case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
	case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
		action = XDP_PASS;
		break;
	}

	return action;

error:
	return XDP_ABORTED;
}

#endif
