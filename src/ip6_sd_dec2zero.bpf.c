// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* HIKe Prog Name comes always first */
#define HIKE_PROG_NAME    ip6_sd_dec2zero

#define REAL
//#define REPL

#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <linux/errno.h>

#ifdef REAL
  /* HIKe Chain IDs and XDP eBPF/HIKe programs IDs */
  #include "tb_defs.h"
  #include "hike_vm.h"
  #include "parse_helpers.h"
  #include "ip6_hset.h"
  
#endif  

#ifdef REPL
  #define HIKE_DEBUG 1 
  #include "tb_defs.h"
  #include "ip6_hset_repl.h"
  #include "mock.h"

#endif

#define HIKE_PCPU_LSE_MAX	4096

#define MAP_NAME_1 pcpu_sd_dec2zero

bpf_map(MAP_NAME_1,
	LRU_PERCPU_HASH,
	struct ipv6_hset_srcdst_key,
	struct flow_meter_basic,
	HIKE_PCPU_LSE_MAX);

#ifdef REAL
  #define get_flow(key) \
  bpf_map_lookup_elem(&MAP_NAME_1, key)

  #define add_flow(key, flow) \
  bpf_map_update_elem(&MAP_NAME_1, key, flow, BPF_ANY)
#endif  

#ifdef REPL
  #define get_flow(key) \
  bpf_map_lookup_elem_tb(&MAP_NAME_1, key)

  #define add_flow(key, flow) \
  bpf_map_update_elem_tb(&MAP_NAME_1, key, flow, BPF_ANY)
#endif  


static __always_inline struct flow_meter_basic * set_flow (struct flow_meter_basic * f, 
  U64 in_count)
 {

  f->count = in_count;

  return f;
}   

/* ip6_sd_met_dec ()
 * 
 * per-CPU counter HIKe Program
 * 
 * input:
 * - ARG1:	HIKe Program ID;
 *
 * returns the counter of the packets in HVM_RET
*/
HIKE_PROG(HIKE_PROG_NAME) {

  __u32 start_value = HVM_ARG2;

  U64 ret_code;
  U64 key_miss = 0; 

  struct flow_meter_basic * f;

  FLOW_KEY_TYPE key;
  struct flow_meter_basic my_flow;

  struct pkt_info *info = hike_pcpu_shmem();
  struct hdr_cursor *cur;


	/* take the reference to the cursor object which has been saved into
	 * the HIKe per-cpu shared memory
	 */
	cur = pkt_info_cur(info);
	if (unlikely(!cur))
		goto drop;

  ret_code = ipv6_hset_srcdst_get_key(ctx, cur, &key);
  if (ret_code !=0) {
    goto drop;
  }


  f = get_flow(&key);
  if (f == NULL || f->count == 0) {
    f = &my_flow;
    key_miss = 1;
    set_flow (f, start_value);
  } else {
    if (f>0) { f->count = f->count -1; }
  }
  
  HVM_RET = f->count;

//out:
  if (key_miss) {
    add_flow(&key, f);
  }
	return HIKE_XDP_VM;
drop:

  DEBUG_HKPRG_PRINT("drop packet");
	return HIKE_XDP_ABORTED;
  
  return 0;
}
EXPORT_HIKE_PROG(HIKE_PROG_NAME);
EXPORT_HIKE_PROG_MAP(HIKE_PROG_NAME, MAP_NAME_1);

#ifdef REAL
char LICENSE[] SEC("license") = "Dual BSD/GPL";
#endif