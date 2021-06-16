
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
	HIKE_PCPU_MON_EVENT_ERROR	= 2,
};
#define HIKE_EBPF_PROG_PCPU_MON		14
#define HIKE_EBPF_PROG_IPV6_TOS_CLS	15

enum {
	HIKE_IPV6_TOS_CONTROL_TRAFFIC = 56,
};

#define HIKE_EBPF_PROG_APP_CFG_INIT	16
#define HIKE_EBPF_PROG_APP_CFG_LOAD	17
#define HIKE_EBPF_PROG_APP_CFG_STORE	18

enum {
	HIKE_APP_CFG_KEY_UNSPEC		= 0,
	HIKE_APP_CFG_KEY_NETSTATE	= 1,
};

enum {
	HIKE_APP_CFG_VAL_NESTATE_UNSPEC  = 0,
	HIKE_APP_CFG_VAL_NESTATE_OK	 = HIKE_APP_CFG_VAL_NESTATE_UNSPEC,
	HIKE_APP_CFG_VAL_NESTATE_CRIT	 = 1,
};


/* HIKe Chain IDs (ID must be > 64 (0x40)) */

#define HIKE_CHAIN_FOO_ID		76 /* 0x4c */
#define HIKE_CHAIN_BAR_ID		77 /* 0x4d */
#define HIKE_CHAIN_BAZ_ID		78 /* 0x4e */

#define HIKE_CHAIN_QUX_ID		79 /* 0x4f */
#define HIKE_CHAIN_MON_ALLOW		80 /* 0x50 */
#define HIKE_CHAIN_MON_DROP		81 /* 0x51 */

#endif
