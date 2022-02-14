
#ifndef _HIKE_VM_STRING_H
#define _HIKE_VM_STRING_H

#include "hike_vm.h"

#define __HIKE_MEMMOVE_BIT		8
#define __HIKE_MEMOVE_LEN_MAX		(BIT(__HIKE_MEMMOVE_BIT + 1) - 1)

#if __HIKE_MEMMOVE_BIT >= HIKE_MEM_BANK_PCPU_SHARED_HDATA_BIT
#error "per-CPU HIKe VM reserved shared memory is too small"
#endif

/* builtin memcpy is not very efficient...
 * let's do it manually in order to avoid dummy misaligned copies... oh!
 */
#define ___memmove_chunk___(BUF, TO, FROM, LEN, TYPE) 			\
do {									\
	TYPE *__p0, *__p1;						\
	unsigned int i;							\
									\
	/* it is going to be unrolled by the compiler */		\
	for (i = 0; i < (LEN)/sizeof(TYPE); ++i) {			\
		__p0 = (TYPE *)(BUF);					\
		__p1 = (TYPE *)(FROM) + i;				\
		*__p0 = *__p1;						\
		__p1 = (TYPE *)(TO) + i;				\
		*__p1 = *__p0;						\
	}								\
	(TO) += (LEN);							\
	(FROM) += (LEN);						\
} while(0)

static __always_inline int
hike_memmove(unsigned char *to, const unsigned char *from, unsigned long len,
	     const unsigned char *end)
{
	struct hike_shared_mem_data *__shmem;
	unsigned long mask, left;
	unsigned char *data;
	int rc, i;

	if (unlikely(!len))
		return 0;
	if (unlikely(len > __HIKE_MEMOVE_LEN_MAX))
		return -E2BIG;

	__shmem = hike_pcpu_shmem();
	if (unlikely(!__shmem))
		return -ENOMEM;
	/* no need to check for NULL here */
	data = &__shmem->__hvm_data[0];

	/* let's start to move data */
	for (rc = 0, left = len, i = 0; i < __HIKE_MEMMOVE_BIT + 1;
	     ++i, left >>= 1) {
		if (!left)
			break;

		mask = len & BIT(i);
		if (!mask)
			continue;

#define ___side_effect_check_bounds___(LEN)				\
	if (unlikely((to + (LEN) > end) ||				\
		     (from + (LEN) > end))) {				\
		rc = -ENOBUFS;						\
		goto out;						\
	}

#define ___side_effect_memmove___(LEN)					\
	case (LEN):							\
		___side_effect_check_bounds___(LEN);			\
		goto __L##LEN;

#define ___side_effect_memmove_chunk___(LEN, TYPE)			\
	___memmove_chunk___(data, to, from, LEN, TYPE)

#define ___CASE_MAX	256
		build_bug_on(___CASE_MAX != BIT(__HIKE_MEMMOVE_BIT));

		switch (BIT(i)) {
		case ___CASE_MAX:
			___side_effect_check_bounds___(___CASE_MAX);

/* 256 */		___side_effect_memmove_chunk___(128, __u64);
__L128:			___side_effect_memmove_chunk___(64, __u64);
__L64:			___side_effect_memmove_chunk___(32, __u64);
__L32:			___side_effect_memmove_chunk___(16, __u64);
__L16:			___side_effect_memmove_chunk___(8, __u64);
__L8:			___side_effect_memmove_chunk___(4, __u32);
__L4:			___side_effect_memmove_chunk___(2, __u16);
__L2:			___side_effect_memmove_chunk___(1, __u8);
__L1:			___side_effect_memmove_chunk___(1, __u8);
			break;
		___side_effect_memmove___(128);
		___side_effect_memmove___(64);
		___side_effect_memmove___(32);
		___side_effect_memmove___(16);
		___side_effect_memmove___(8);
		___side_effect_memmove___(4);
		___side_effect_memmove___(2);
		___side_effect_memmove___(1);
		default:
			rc = -EOPNOTSUPP;
			goto out;
		}
#undef ___CASE_MAX

#undef ___side_effect_memmove_chunk_8___
#undef ___side_effect_memmove__
#undef ___side_effect_check_bounds___
	}
out:
	return rc;
}

#endif
