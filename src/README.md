ip6_hset_srcdst.bpf.c
ip6_sd_tbmon.bpf.c
ip6_dst_tbmon.bpf.c
ip6_sd_meter.bpf.c
ip6_dst_meter.bpf.c


/* 
 * ip6_hset_srcdst.bpf.c
 * IPv6 Hashset on ip6 (src,dst)
 *
 * The program allows the user to interact with the IPv6 <DA,SA> HSet.
 * Based on the action argument (ARG2), the program is able to:
 *   i) with ARG2 == IPV6_HSET_ACTION_LOOKUP, check whether the packet is in
 *	the blacklist or not;
 *  ii) with ARG2 == IPV6_HSET_ACTION_ADD, add the packet to the blacklist if
 *	it is not already present.
 * iii) with ARG2 == IPV6_HSET_ACTION_LOOKUP_AND_CLEAN, add the packet to the
 *	blacklist if it is not already present and clean up an expired entry.
 *
 * input:
 * - ARG1:	HIKe Program ID;
 * - ARG2:	action
 *
 * output:
 *  - REG0:	ret code operation
 */



# 
# ip6_sd_tbmon.bpf.c
# 
# 
# ip6_dst_tbmon.bpf.c
# 

ip6_sd_meter.bpf.c


ip6_dst_meter.bpf.c






