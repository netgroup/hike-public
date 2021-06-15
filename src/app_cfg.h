
#ifndef __APP_CFG_H
#define __APP_CFG_H

#include <stddef.h>
#include <linux/in.h>
#include <linux/errno.h>

#include "hike_vm.h"

#define HIKE_APP_CFG_MAP_SIZE		128
bpf_map(map_app_cfg, HASH, __u32, __u32, HIKE_APP_CFG_MAP_SIZE);

#endif
