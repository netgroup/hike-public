
#ifndef _MAP_H
#define _MAP_H

#include <linux/bpf.h>
#include <linux/btf.h>
#include <bpf/bpf_helpers.h>

#include "hike_vm_common.h"

#define btf_bpf_map_section(name) __section(".btf.maps."stringify(name))

#define bpf_map(name, _type, type_key, type_val, _max_entries)		\
struct bpf_map_def SEC("maps") name = {                         	\
        .type        = EVAL_CAT_2(BPF_MAP_TYPE_, _type),		\
        .key_size    = sizeof(type_key),                        	\
        .value_size  = sizeof(type_val),                        	\
        .max_entries = _max_entries,                            	\
};                                                              	\
struct HIKE_VM_BTF_MAP_NAME(name) {					\
        type_key key;                                           	\
        type_val value;                                         	\
};                                                              	\
struct HIKE_VM_BTF_MAP_NAME(name) btf_bpf_map_section(name)		\
	HIKE_VM_BTF_MAP_NAME(name) = { 0, }

#endif
