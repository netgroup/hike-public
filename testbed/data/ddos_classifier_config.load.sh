#!/bin/bash


bpftool map update pinned /sys/fs/bpf/maps/init/map_ipv6		\
	key hex		00 12 00 01 00 00 00 00 00 00 00 00 00 00 00 02 \
	value hex 	54 00 00 00
