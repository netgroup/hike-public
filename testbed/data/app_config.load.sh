#!/bin/bash

./data/set_network_state.sh ok

# Add the network state key setting the default value to "OK".
# bpftool map update 						\
# 	pinned /sys/fs/bpf/maps/appcfg/map_app_cfg		\
# 		key hex		01 00 00 00 			\
# 		value hex 	00 00 00 00
