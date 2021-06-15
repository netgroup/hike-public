
#ifndef _MINIMAL_H
#define _MINIMAL_H

/* ######################################################################### */
/* ########## Those definitions should be imported in some way ... ######### */
/* ######################################################################### */


#define HIKE_DEBUG			1

/* eBPF/HIKe Program IDs */
#define HIKE_EBPF_PROG_ALLOW_ANY	11
#define HIKE_EBPF_PROG_DROP_ANY		12
#define HIKE_EBPF_PROG_COUNT_PACKET	13

enum {
	HIKE_PCPU_MON_EVENT_DROP	= 0,
	HIKE_PCPU_MON_EVENT_ALLOW	= 1,
};
#define HIKE_EBPF_PROG_PCPU_MON		14
#define HIKE_EBPF_PROG_IPV6_TOS_CLS	15


/* HIKe Chain IDs (ID must be > 64 (0x40)) */

#define HIKE_CHAIN_FOO_ID		76 /* 0x4c */
#define HIKE_CHAIN_BAR_ID		77 /* 0x4d */
#define HIKE_CHAIN_BAZ_ID		78 /* 0x4e */

#endif
