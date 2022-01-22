// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* This is a self contained HIKe eBPF Program which contains the the HIKe VM
 * structures used to generate BTF info.
 */
#include "hike_vm.h"

HIKE_PROG(hikevm)
{
	return HIKE_XDP_VM;
}
EXPORT_HIKE_PROG(hikevm);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
