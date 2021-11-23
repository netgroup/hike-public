// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* HIKe Prog Name comes always first */
#define HIKE_PROG_NAME    ip6_sd_tbmon

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

  extern U64 REQUIRED_TOKENS;
  extern U64 INJECTED_DELTA;

#endif

#define HIKE_PCPU_LSE_MAX	4096

#define MAP_NAME_1 pcpu_sd_tbmon

bpf_map(MAP_NAME_1,
	LRU_PERCPU_HASH,
	struct ipv6_hset_srcdst_key,
	struct flow,
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


static __always_inline struct flow * set_flow (struct flow * f, 
  U64 in_rate,
  U64 in_bucket_size,
  U64 in_base_time_bits, 
  U64 in_shift_tokens) {

  f->rate = in_rate;
  f->bucket_size = in_bucket_size;
  f->base_time_bits = in_base_time_bits;
  f->shift_tokens = in_shift_tokens;

  //f->last_tokens THIS IS NOT SET, IT IS RESPONSIBILITY OF THE CALLER
  //f->last_time THIS IS NOT SET, IT IS RESPONSIBILITY OF THE CALLER
  return f;
}   

/* ip6_srcdst_tb_mon ()
 * 
 * per-CPU Token Bucket Monitor HIKe Program
 * 
 * input:
 * - ARG1:	HIKe Program ID;
 *
 * returns IN_PROFILE, OUT_PROFILE in HVM_RET
*/
HIKE_PROG(HIKE_PROG_NAME) {

  U64 current_time;
  U64 delta;
  U64 new_tokens;
  U64 ret_code ;
  U64 required_tokens;
  U64 key_miss = 0; 

  struct flow * f;

  FLOW_KEY_TYPE key;
  struct flow my_flow;

  struct pkt_info *info = hike_pcpu_shmem();
  struct hdr_cursor *cur;

  DEBUG_PRINT("Hi there!");

  /* take the reference to the cursor object which has been saved into
	 * the HIKe per-cpu shared memory
	 */
	cur = pkt_info_cur(info);
	if (unlikely(!cur))
		goto drop;

  current_time = GET_TIME;

  ret_code = ipv6_hset_srcdst_get_key(ctx, cur, &key);
  if (ret_code !=0) {
    goto drop;
  }

  required_tokens = 1;
#ifdef REPL
  required_tokens = REQUIRED_TOKENS;
#endif

  //get_tokens_from_pkt(ctx, cur, &required_tokens);

  f = get_flow(&key);
  if (f == NULL | f->rate == 0) {
    f = &my_flow;
    key_miss = 1;
    set_flow (f, RATE, BUCKET_SIZE, BASE_TIME_BITS, SHIFT_TOKENS);
    required_tokens = required_tokens << SHIFT_TOKENS;
    new_tokens=BUCKET_SIZE;
    f->last_time=current_time;
  } else {
    required_tokens = required_tokens << f->shift_tokens;
    delta = current_time - f->last_time;
#ifdef REPL
    delta = INJECTED_DELTA;
    current_time = f->last_time + INJECTED_DELTA;
#endif
    if (delta >> LOG2_MAX_DELTA) {  // if delta [ns] > 2^LOG2_MAX_DELTA
      f->last_time=current_time;
      new_tokens=f->bucket_size;
    } else {
      delta = (delta * f->rate) >> f->base_time_bits;
      if(delta>0){
        f->last_time=current_time;
        new_tokens=f->last_tokens + delta ;
        if (new_tokens>f->bucket_size) {
          new_tokens=f->bucket_size;
        } 
      } else {
        new_tokens=f->last_tokens;
      }
    }
  }
  //DEBUG_PRINT("REQUIRED %llu",required_tokens);
  //DEBUG_PRINT("NEW %llu",new_tokens);
  
  if(required_tokens>new_tokens){
    f->last_tokens=new_tokens;
    HVM_RET = OUT_PROFILE;
    goto out;
  } else {
    new_tokens=new_tokens-required_tokens;
    f->last_tokens=new_tokens;
    HVM_RET = IN_PROFILE;
    goto out;
  }

out:
  if (key_miss) {
    add_flow(&key, f);
  }
	return HIKE_XDP_VM;
drop:
  DEBUG_PRINT("drop packet");
	return HIKE_XDP_ABORTED;

  return 0;
}
EXPORT_HIKE_PROG(HIKE_PROG_NAME);
EXPORT_HIKE_PROG_MAP(HIKE_PROG_NAME, MAP_NAME_1);

#ifdef REAL
char LICENSE[] SEC("license") = "Dual BSD/GPL";
#endif
