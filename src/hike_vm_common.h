
#ifndef _HIKE_VM_COMMON_H
#define _HIKE_VM_COMMON_H

#include <stddef.h>

#include <linux/errno.h>
#include <linux/bpf.h>
#include <linux/btf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* compiler and low level machinery */

#ifndef ___constant_swab16
#define ___constant_swab16(x) ((__u16)(		\
	(((__u16)(x) & (__u16)0x00ffU) << 8) |	\
	(((__u16)(x) & (__u16)0xff00U) >> 8)))
#endif

#ifndef ___constant_swab32
#define ___constant_swab32(x) ((__u32)(			\
	(((__u32)(x) & (__u32)0x000000ffUL) << 24) |	\
	(((__u32)(x) & (__u32)0x0000ff00UL) <<  8) |	\
	(((__u32)(x) & (__u32)0x00ff0000UL) >>  8) |	\
	(((__u32)(x) & (__u32)0xff000000UL) >> 24)))
#endif

#ifndef ___constant_swab64
#define ___constant_swab64(x) ((__u64)(				\
	(((__u64)(x) & (__u64)0x00000000000000ffULL) << 56) |	\
	(((__u64)(x) & (__u64)0x000000000000ff00ULL) << 40) |	\
	(((__u64)(x) & (__u64)0x0000000000ff0000ULL) << 24) |	\
	(((__u64)(x) & (__u64)0x00000000ff000000ULL) <<  8) |	\
	(((__u64)(x) & (__u64)0x000000ff00000000ULL) >>  8) |	\
	(((__u64)(x) & (__u64)0x0000ff0000000000ULL) >> 24) |	\
	(((__u64)(x) & (__u64)0x00ff000000000000ULL) >> 40) |	\
	(((__u64)(x) & (__u64)0xff00000000000000ULL) >> 56)))
#endif

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__

#define __hike_cpu_to_be16(x)	((__u16)(__be16)(x))
#define __hike_cpu_to_be32(x)	((__u32)(__be32)(x))
#define __hike_cpu_to_be64(x)	((__u64)(__be64)(x))

#define __hike_cpu_to_le16(x)	___constant_swab16(x)
#define __hike_cpu_to_le32(x)	___constant_swab32(x)
#define __hike_cpu_to_le64(x)	___constant_swab64(x)

#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

#define __hike_cpu_to_be16(x)	___constant_swab16(x)
#define __hike_cpu_to_be32(x)	___constant_swab32(x)
#define __hike_cpu_to_be64(x)	___constant_swab64(x)

#define __hike_cpu_to_le16(x)	((__u16)(__le16)(x))
#define __hike_cpu_to_le32(x)	((__u32)(__le32)(x))
#define __hike_cpu_to_le64(x)	((__u64)(__le64)(x))

#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif

#define cpu_to_be16(x)	__hike_cpu_to_be16(x)
#define cpu_to_be32(x)	__hike_cpu_to_be32(x)
#define cpu_to_be64(x)	__hike_cpu_to_be64(x)

#define cpu_to_le16(x)	__hike_cpu_to_le16(x)
#define cpu_to_le32(x)	__hike_cpu_to_le32(x)
#define cpu_to_le64(x)	__hike_cpu_to_le64(x)

#ifndef BIT
#define BIT(x) (1 << (x))
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#endif

#ifndef memset
#define memset(dest, val, n) __builtin_memset((dest), (val), (n))
#endif

#ifndef bpf_htonll
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_htonll(x) (x)
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
__be64 __always_inline bpf_htonll(__u64 val)
{
	__be64 low, hi;
	__be64 ret;

	hi = ((__be64)bpf_htonl((__u32)(val & 0xffffffff))) << (32ul);
	low = bpf_htonl((__be32)(val >> (32ul)));

	ret = hi | low;
	return ret;
}
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif
#endif

/* macro concatenation */
#define ___CAT_1(a)			a
#define __CAT_1(a)			___CAT_1(a)
#define EVAL_CAT_1(a)			__CAT_1(a)

#define ___CAT_2(a, b)			a##b
#define __CAT_2(a, b)			___CAT_2(a, b)
#define EVAL_CAT_2(a, b)		__CAT_2(a, b)

#define ___CAT_3(a, b, c)		a##b##c
#define __CAT_3(a, b, c)		___CAT_3(a, b, c)
#define EVAL_CAT_3(a, b, c)		__CAT_3(a, b, c)

#define ___CAT_4(a, b, c, d)		a##b##c##d
#define __CAT_4(a, b, c, d)		___CAT_4(a, b, c, d)
#define EVAL_CAT_4(a, b, c, d)		__CAT_4(a, b, c, d)

#define ___CAT_5(a, b, c, d, e)		a##b##c##d##e
#define __CAT_5(a, b, c, d, e)		___CAT_5(a, b, c, d, e)
#define EVAL_CAT_5(a, b, c, d, e)	__CAT_5(a, b, c, d, e)

#define ___CAT_6(a, b, c, d, e, f)	a##b##c##d##e##f
#define __CAT_6(a, b, c, d, e, f)	___CAT_6(a, b, c, d, e, f)
#define EVAL_CAT_6(a, b, c, d, e, f)	__CAT_6(a, b, c, d, e, f)

#define __stringify(X)		#X
#define stringify(X)		__stringify(X)

/* definition of section */
#ifndef __section
#define __section(NAME)					\
	__attribute__((section(NAME), used))
#endif

/* BTF map name prefix */
#define HIKE_VM_BTF_MAP_PREFIX ____btf_map

#define HIKE_VM_BTF_MAP_NAME(name) 			\
	EVAL_CAT_3(HIKE_VM_BTF_MAP_PREFIX, _, name)

#endif
