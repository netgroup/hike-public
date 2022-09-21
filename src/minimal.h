
#ifndef _MINIMAL_H
#define _MINIMAL_H

/* ######################################################################### */
/* ########## Those definitions should be imported in some way ... ######### */
/* ######################################################################### */


#ifndef __HIKE_CFLAGS_EXTMAKE
#define HIKE_DEBUG			1

/* eBPF/HIKe Program IDs */
#define HIKE_EBPF_PROG_ALLOW_ANY	11
#define HIKE_EBPF_PROG_DROP_ANY		12
#define HIKE_EBPF_PROG_COUNT_PACKET	13

enum {
	HIKE_PCPU_MON_EVENT_DROP	= 0,
	HIKE_PCPU_MON_EVENT_ALLOW	= 1,
	HIKE_PCPU_MON_EVENT_ERROR	= 2,
	HIKE_PCPU_MON_EVENT_SET_ECN	= 3,
	HIKE_PCPU_MON_EVENT_REDIRECT	= 4,
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
	HIKE_APP_CFG_KEY_COLLECTOR_OIF	= 2,
};

enum {
	HIKE_APP_CFG_VAL_NESTATE_UNSPEC  = 0,
	HIKE_APP_CFG_VAL_NESTATE_OK	 = HIKE_APP_CFG_VAL_NESTATE_UNSPEC,
	HIKE_APP_CFG_VAL_NESTATE_CRIT	 = 1,
};

#define HIKE_EBPF_PROG_TLCL_DO_STUFF	19
#define HIKE_EBPF_PROG_REDIRECT		20
#define HIKE_EBPF_PROG_L2XCON		21

#define HIKE_EBPF_PROG_MMFWD		22 /* 0x16 */
#define HIKE_EBPF_PROG_IPV6_SET_ECN	23 /* 0x17 */
#define HIKE_EBPF_PROG_TRACE_PASS	24 /* 0x18 */
#define HIKE_EBPF_PROG_IPV6_KROUTE	25 /* 0x19 */
#define HIKE_EBPF_PROG_TRACE_DROP	26 /* 0x1a */

#define HIKE_EBPF_PROG_IPV6_HSET_SRCDST 27 /* 0x1b */

/* FIXME: add missing _PROG_ in macro name */
#define HIKE_EBPF_HIKE_PASS		28 /* 0x1c */
#define HIKE_EBPF_HIKE_DROP		29 /* 0x1d */

#define HIKE_EBPF_PROG_LSE		30 /* 0x1e */

#define HIKE_EBPF_PROG_L2RED		31 /* 0x1f */

#define HIKE_EBPF_PROG_IPV6_FND_UDP	32 /* 0x20 */

#define HIKE_EBPF_PROG_HIKE_VERBOSE	33 /* 0x21 */

#define HIKE_EBPF_PROG_SR6_INLINE_UDP	34 /* 0x22 */

#define HIKE_EBPF_PROG_SR6_ENCAP	35 /* 0x23 */

/* Chain IDs
 * Each chain ID must have the 30-th bit (counting from 0) SET to 1.
 */
#define HIKE_CHAIN_FOO_ID		1073741900 /* 0x4000004c */
#define HIKE_CHAIN_BAR_ID		1073741901 /* 0x4000004d */
#define HIKE_CHAIN_BAZ_ID		1073741902 /* 0x4000004e */

#define HIKE_CHAIN_QUX_ID		1073741903 /* 0x4000004f */
#define HIKE_CHAIN_MON_ALLOW		1073741904 /* 0x40000050 */
#define HIKE_CHAIN_MON_DROP		1073741905 /* 0x40000051 */

#define HIKE_CHAIN_TLCL_TEST_ID		1073741906 /* 0x40000052 */

#define HIKE_CHAIN_DDOS_MMFDW_ID	1073741907 /* 0x40000053 */
#define HIKE_CHAIN_DDOS_3STAGES_ID	1073741908 /* 0x40000054 */
#define HIKE_CHAIN_DDOS_2STAGES_ID	1073741909 /* 0x40000055 */

/* (1 << 30) is the Chain ID FLAG used to discriminate a Chain ID from an HIKe
 * eBPF Program.
 * you can assign a Chain ID as follow:
 *
 * 0x40000000 | ChainID
 */
#define HIKE_CHAIN_DDOS_FULL_ID		1073741910 /* 0x40000056 */

#define HIKE_CHAIN_DDOS_FULL_RED_ID	1073741911 /* 0x40000057 */

#define HIKE_CHAIN_EVAL_DELAY_ID	1073741912 /* 0x40000058 */

#define HIKE_CHAIN_SR6_INLINE_UDP	1073741913 /* 0x40000059 */

#define HIKE_CHAIN_SR6_ENCAP		1073741914 /* 0x4000005a */

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ RAW ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

#ifndef TLCL_MAX_DEPTH
/* default depth is 4, 3 do_stuff() and 1 X-connect */
#define TLCL_MAX_DEPTH			4
#endif

#define RAW_TLCL_EBPF_DO_STUFF		1
#define RAW_TLCL_EBPF_L2XCON		2

#else /* !__HIKE_CFLAGS_EXTMAKE */
	/* here if __HIKE_CFLAGS_EXTMAKE is defined */
#endif
#endif
