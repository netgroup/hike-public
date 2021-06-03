#!/bin/bash


bpftool map update pinned /sys/fs/bpf/maps/init/map_ipv6		\
	key hex		fc 01 00 00 00 00 00 00 00 00 00 00 00 00 00 02 \
	value hex 	4e 00 00 00
