
#ifndef _HIKE_VM_STRING_H
#define _HIKE_VM_STRING_H

#include "hike_vm.h"

#define __HIKE_MEMMOVE_BIT		9
#define __HIKE_MEMOVE_LEN_MAX		BIT(__HIKE_MEMMOVE_BIT)

#if __HIKE_MEMMOVE_BIT >= HIKE_MEM_BANK_PCPU_SHARED_HDATA_BIT
#error "per-CPU HIKe VM reserved shared memory is too small"
#endif

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
	if (unlikely(len >= __HIKE_MEMOVE_LEN_MAX))
		return -E2BIG;

	__shmem = hike_pcpu_shmem();
	if (unlikely(!__shmem))
		return -ENOMEM;
	/* no need to check for NULL here */
	data = &__shmem->__hvm_data[0];

/* builtin memcpy is not very efficient...
 * let's do it manually in order to avoid dummy misaligned copies... oh!
 */
#define ___memmove___(BUF, TO, FROM, B, TYPE)				\
do {									\
	struct __s {							\
		TYPE dummy[B];						\
	} *__p0, *__p1;							\
									\
	__p0 = (struct __s *)(BUF);					\
	__p1 = (struct __s *)(FROM);					\
	*__p0 = *__p1;							\
	__p1 = (struct __s *)(TO);					\
	*__p1 = *__p0;							\
} while (0)

#define ___side_effect_memmove___(N, LEN, TYPE)				\
	case (N):							\
		build_bug_on((N) >= __HIKE_MEMMOVE_BIT);		\
		if (unlikely(to + BIT(N) > end ||			\
			     from + BIT(N) > end)) {			\
			rc = -ENOMEM;					\
			goto out;					\
		}							\
		___memmove___(data, to, from, LEN, TYPE);		\
		from += BIT(N);						\
		to += BIT(N);						\
		break

#define ___side_effect_memmove_aligned_8___(N)				\
	___side_effect_memmove___(N, (BIT(N)/sizeof(__u64)), __u64)

	for (rc = 0, left = len, i = 0; i < __HIKE_MEMMOVE_BIT; ++i,
	     left >>= 1) {
		if (unlikely(rc < 0))
			return rc;
		if (!left)
			break;

		mask = len & BIT(i);
		if (!mask)
			continue;

		switch (i) {
		___side_effect_memmove_aligned_8___(8);
		___side_effect_memmove_aligned_8___(7);
		___side_effect_memmove_aligned_8___(6);
		___side_effect_memmove_aligned_8___(5);
		___side_effect_memmove_aligned_8___(4);
		___side_effect_memmove_aligned_8___(3);
		/* if we are not aligned to 64 bit anymore */
		___side_effect_memmove___(2, BIT(2) >> 2, __u32);
		___side_effect_memmove___(1, BIT(1) >> 1, __u16);
		___side_effect_memmove___(0, BIT(0), __u8);
		default:
			rc = -EOPNOTSUPP;
			goto out;
		}
	}

#undef ___side_effect_memmove_aligned_8___
#undef ___side_effect_memmove___
#undef ___memmove___

out:
	return rc;
}

#endif
