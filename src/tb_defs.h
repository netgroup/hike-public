#ifndef _TB_DEFS_H 
#define _TB_DEFS_H

#ifndef REAL
  #ifndef REPL
    #error REPL or REAL must be defined!
  #endif
#endif

#ifdef REAL
  #ifdef REPL
    #error REPL and REAL cannot be defined both!
  #endif
#endif


#include <linux/in6.h>

//rate : 10000 token/s bucket size : 100 
//#define TB_DEFAULT 1

//rate : 100000 token/s bucket size : 1000 
//#define TB_DEFAULT 2

//rate : 20 token/s bucket size : 5 
#define TB_DEFAULT 3


#define U64 __u64
//#define __u64 unsigned long long
//#define FLOW_KEY_TYPE unsigned long 
#define FLOW_KEY_TYPE struct ipv6_hset_srcdst_key
#define FLOW_KEY_TYPE_SRC struct ipv6_hset_src_key
#define FLOW_KEY_TYPE_DST struct ipv6_hset_dst_key
#define E_INVAL -3
#define E_NO_KEY -2
#define OUT_PROFILE -1
#define IN_PROFILE 0
#ifdef REPL
  #define GET_TIME get_nanosec_time()
#endif
#ifdef REAL
  #define GET_TIME bpf_ktime_get_ns();
#endif
#define GIGA 1000000000
#define MEGA 1000000

// if delta [ns] > 2^LOG2_MAX_DELTA then the bucket is filled to its maximum size
#define LOG2_MAX_DELTA 32

#if TB_DEFAULT == 1
  #define RATE 10995116 
  #define BUCKET_SIZE 102400
  #define BASE_TIME_BITS 30
  #define SHIFT_TOKENS 10
#endif

#if TB_DEFAULT == 2
  #define RATE 109951162 
  #define BUCKET_SIZE 1024000
  #define BASE_TIME_BITS 30
  #define SHIFT_TOKENS 10
#endif

//rate : 20 token/s bucket size : 5 
#if TB_DEFAULT == 3
  #define RATE 22517998 
  #define BUCKET_SIZE 5242880
  #define BASE_TIME_BITS 30
  #define SHIFT_TOKENS 20
#endif


/*
  rate is expressed in (tokens/(2^shift_tokens)) / (2^base_time_bits ns)
  bucket_size is expressed in tokens/(2^shift_tokens) 
  last_tokens is expressed in tokens/(2^shift_tokens)
  last_time is expressed in ns
*/
struct flow {
  U64 rate;
  U64 bucket_size;
  U64 last_tokens;
  U64 last_time;
  U64 base_time_bits;   
  U64 shift_tokens;     
} ;

/*

*/
struct flow_meter_basic {
  U64 count;
} ;


#endif
