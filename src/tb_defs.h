#define REAL
//#define REPL

//rate : 10000 token/s bucket size : 100 
//#define TB_DEFAULT 1

//rate : 100000 token/s bucket size : 1000 
#define TB_DEFAULT 2


#define U64 __u64
//#define __u64 unsigned long long
//#define FLOW_KEY_TYPE unsigned long 
#define FLOW_KEY_TYPE struct ipv6_hset_srcdst_key
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
