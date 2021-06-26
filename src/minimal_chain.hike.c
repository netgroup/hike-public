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

HIKE_CHAIN_1(HIKE_CHAIN_FOO_ID)
{
#define __ETH_PROTO_TYPE_ABS_OFF	12
#define __IPV4_TOTAL_LEN_ABS_OFF	16
#define __IPV6_HOP_LIM_ABS_OFF		21
	__u16 eth_type;
	__u8 allow = 1;			/* allow any by default */
	__u16 ip4_len;
	__u8 hop_lim;

	hike_packet_read_u16(&eth_type, __ETH_PROTO_TYPE_ABS_OFF);
	if (eth_type == 0x800) {
		hike_packet_read_u16(&ip4_len, __IPV4_TOTAL_LEN_ABS_OFF);
		if (ip4_len >= 128)
			goto out;

		/* drop any IPv4 packet if IPv4 Total Len  < 128 */
		allow = 0;
		goto out;
	}

	if (eth_type == 0x86dd) {
		/* change the TTL of the IPv6 packet */
		hike_packet_read_u8(&hop_lim, __IPV6_HOP_LIM_ABS_OFF);
		if (hop_lim != 64)
			goto out;

		/* rewrite the hop_limit */
		hike_packet_write_u8(__IPV6_HOP_LIM_ABS_OFF, 17);
	}

out:
	hike_elem_call_3(HIKE_CHAIN_BAR_ID, allow, eth_type);

	return 0;
#undef __ETH_PROTO_TYPE_ABS_OFF
#undef __IPV4_TOTAL_LEN_ABS_OFF
#undef __IPV6_HOP_LIM_ABS_OFF
}

HIKE_CHAIN_3(HIKE_CHAIN_BAR_ID, __u8, allow, __u16, eth_type)
{
	__u32 prog_id = allow ? HIKE_EBPF_PROG_ALLOW_ANY :
				HIKE_EBPF_PROG_DROP_ANY;
	/* FIXME: counter is an u64 but for the moment we consider it u16;
	 * shift operators still need to be implemented in HIKe VM...
	 */
	__u8 override = 0;
	__u16 counter;

	/* let's count the number of processed packet based on the allow flag.
	 * In counter we have the number of allowed or dropped packets, so far.
	 */
	counter = hike_elem_call_2(HIKE_EBPF_PROG_COUNT_PACKET, allow);
	if (allow)
		goto out;

	if ((__s16)counter < 0) {
		prog_id = HIKE_EBPF_PROG_DROP_ANY;
		override = 1;
	} else if (counter >= 32) {
		/* when the number of dropped packet is above a given
		 * threshold, override the prog and the alow code.
		 */
		prog_id = HIKE_EBPF_PROG_ALLOW_ANY;
		override = 1;
	}

	if (override)
		/* increase also the override counter rather than allow or
		 * drop. We can call the same program many times (until you do
		 * not hit the tail call limit.
		 */
		hike_elem_call_2(HIKE_EBPF_PROG_COUNT_PACKET, 2);
out:
	hike_elem_call_2(prog_id, eth_type);

	/* prog_id is a final HIKe Program, we should not return from this
	 * call. If we return from that call, it means that we have experienced
	 * some issues... so the HIKe VM applies the default policy on such a
	 * packet.
	 */
	return 0;
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

#define PCPU_MON_INC_ALLOW()					\
	hike_elem_call_2(HIKE_EBPF_PROG_PCPU_MON,		\
			 HIKE_PCPU_MON_EVENT_ALLOW)

#define PCPU_MON_INC_DROP()					\
	hike_elem_call_2(HIKE_EBPF_PROG_PCPU_MON,		\
			 HIKE_PCPU_MON_EVENT_DROP)


#define IPV6_ICMP_PROTO			58

HIKE_CHAIN_1(HIKE_CHAIN_BAZ_ID)
{
	struct pkt_info *info = UAPI_PCPU_SHMEM_ADDR;
	struct hdr_cursor *cur = pkt_info_cur(info);
	__u16 nexthdr_off;
	__u16 eth_type;
	__u8 nexthdr;
	__u8 tos;

	hike_packet_read_u16(&eth_type, offsetof(struct ethhdr, h_proto));

	/* TODO: handle the tos wich can be an error code... */
	tos = hike_elem_call_1(HIKE_EBPF_PROG_IPV6_TOS_CLS);
	if (tos == 0x04)
		goto allow;

	/* evaluate dinamically the offset of the nexthdr field in the IPv6
	 * header.
	 * Then, we load the nexthdr value accessing directly the packet.
	 */
	nexthdr_off = cur->nhoff + offsetof(struct ipv6hdr, nexthdr);
	hike_packet_read_u8(&nexthdr, nexthdr_off);
	if (nexthdr == IPV6_ICMP_PROTO) {	
		PCPU_MON_INC_DROP();
		/* drop only ICMP messages */
		hike_elem_call_2(HIKE_EBPF_PROG_DROP_ANY, eth_type);
		goto fallback;
	}

allow:
	PCPU_MON_INC_ALLOW();
	hike_elem_call_2(HIKE_EBPF_PROG_ALLOW_ANY, eth_type);
fallback:
	/* for the moment, we return 0; however in a fallback path we should
	 * notify the event to the HIKe VM using a suitable error code.
	 */
	return 0;
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

#define allow(ETH_TYPE) \
	hike_elem_call_2(HIKE_EBPF_PROG_ALLOW_ANY, (ETH_TYPE))

#define drop(ETH_TYPE) \
	hike_elem_call_2(HIKE_EBPF_PROG_DROP_ANY, (ETH_TYPE))

#define PCPU_MON_INC_ERROR()					\
	hike_elem_call_2(HIKE_EBPF_PROG_PCPU_MON,		\
			 HIKE_PCPU_MON_EVENT_ERROR)

#define ipv6_tos_cls() \
	hike_elem_call_1(HIKE_EBPF_PROG_IPV6_TOS_CLS)

#define app_cfg_load(KEY) \
	hike_elem_call_2(HIKE_EBPF_PROG_APP_CFG_LOAD, (KEY))

HIKE_CHAIN_1(HIKE_CHAIN_MON_ALLOW)
{
	struct pkt_info *info = UAPI_PCPU_SHMEM_ADDR;
	struct hdr_cursor *cur = pkt_info_cur(info);
	__u16 eth_type_off;
	__u16 eth_type;

	eth_type_off = cur->mhoff + offsetof(struct ethhdr, h_proto);
	hike_packet_read_u16(&eth_type, eth_type_off);

	PCPU_MON_INC_ALLOW();

	allow(eth_type);

	/* fallback */
	return 0;
}
#define mon_and_allow() \
	hike_elem_call_1(HIKE_CHAIN_MON_ALLOW)

HIKE_CHAIN_1(HIKE_CHAIN_MON_DROP)
{
	struct pkt_info *info = UAPI_PCPU_SHMEM_ADDR;
	struct hdr_cursor *cur = pkt_info_cur(info);
	__u16 eth_type_off;
	__u16 eth_type;

	eth_type_off = cur->mhoff + offsetof(struct ethhdr, h_proto);
	hike_packet_read_u16(&eth_type, eth_type_off);

	PCPU_MON_INC_DROP();

	drop(eth_type);

	/* fallback */
	return 0;
}
#define mon_and_drop() \
	hike_elem_call_1(HIKE_CHAIN_MON_DROP)

HIKE_CHAIN_1(HIKE_CHAIN_QUX_ID)
{
	/* app_cfg_load returns a signed 64-bit value in case of error.
	 * However, NETSTATE key returns a value which is [0, U16_MAX/2 - 1] in
	 * case of success. Therefore, in case of error the msb of the u16 will
	 * be set to 1.
	 *
	 * XXX NB: that's an hack only for testing purposes... check on __s64
	 * should be done in any case.
	 */
	__s16 val = app_cfg_load(HIKE_APP_CFG_KEY_NETSTATE);
	__u8 state;
	__u8 tos;

	if (val < 0) {
		/* error while retrieving the stte info; drop the packet */
		PCPU_MON_INC_ERROR();
		goto drop;
	}

	/* evaluate ipv6 tos */
	tos = ipv6_tos_cls();

	/* for the sake of semplicity, we consider the state as 8-bit */
	state = val & 0xff;
	switch (state) {
	case HIKE_APP_CFG_VAL_NESTATE_CRIT:
		if (tos != HIKE_IPV6_TOS_CONTROL_TRAFFIC)
			goto drop;

		break;
	}

	mon_and_allow();

	goto fallback;
drop:
	mon_and_drop();
fallback:
	return 0;
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ tailcall test ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

#define do_some_stuff_on_packet() \
	hike_elem_call_1(HIKE_EBPF_PROG_TLCL_DO_STUFF)

#define l2xcon() \
	hike_elem_call_1(HIKE_EBPF_PROG_L2XCON)

HIKE_CHAIN_1(HIKE_CHAIN_TLCL_TEST_ID)
{
#if TLCL_MAX_DEPTH > 0
	__u32 i;

	/* optimizer produces a sub-optimal code... so for performance reasons
	 * it is better to optimize it manually... :-)
	 */
	__asm__ __volatile__
		("r1 = " stringify(HIKE_EBPF_PROG_TLCL_DO_STUFF) "\t\n");
#pragma unroll
	for (i = 1; i <= TLCL_MAX_DEPTH; ++i) {
		//do_some_stuff_on_packet();
		__asm__ __volatile__("call 4352\t\n");
	}
#endif

	/* redirect the packet (cross-connecting two interfaces) */
	l2xcon();

	return 0;
}


/* ~~~~~~~~~~~~~~~~~~~~~~~~ ddos performance test ~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

#define mon_mark_fwd() \
	hike_elem_call_1(HIKE_EBPF_PROG_MMFWD)

HIKE_CHAIN_1(HIKE_CHAIN_DDOS_MMFDW_ID)
{
	mon_mark_fwd();

	return 0;
}

#define ipv6_set_ecn() \
	hike_elem_call_1(HIKE_EBPF_PROG_IPV6_SET_ECN)

#define PCPU_MON_INC_SET_ECN()					\
	hike_elem_call_2(HIKE_EBPF_PROG_PCPU_MON,		\
			 HIKE_PCPU_MON_EVENT_SET_ECN)

#define ipv6_route() \
	hike_elem_call_1(HIKE_EBPF_PROG_IPV6_KROUTE)

HIKE_CHAIN_1(HIKE_CHAIN_DDOS_3STAGES_ID)
{
	/* set the ecn in the dscp field of ipv6 packet */
	ipv6_set_ecn();

	/* step up the event referred to the ecn bit set */
	PCPU_MON_INC_SET_ECN();

	/* route the packet directly */
	ipv6_route();

	return 0;
}

#define trace_pass(__KEY_EVENT) \
	hike_elem_call_2(HIKE_EBPF_PROG_TRACE_PASS, (__KEY_EVENT))

HIKE_CHAIN_1(HIKE_CHAIN_DDOS_2STAGES_ID)
{
	/* set the ecn in the dscp field of ipv6 packet */
	ipv6_set_ecn();

	trace_pass(HIKE_PCPU_MON_EVENT_SET_ECN);

	return 0;
}
