#!/bin/bash

#                     +------------------+      +------------------+
#                     |        TG        |      |       SUT        |
#                     |                  |      |                  |
#                     |         enp6s0f0 +------+ enp6s0f0 <--- HIKe VM XDP loader
#                     |                  |      |                  |
#                     |                  |      |                  |
#                     |         enp6s0f1 +------+ enp6s0f1         |
#                     |                  |      |                  |
#                     +------------------+      +------------------+


TMUX=ebpf
IPP=ip

# Kill tmux previous session
tmux kill-session -t $TMUX 2>/dev/null

# Clean up previous network namespaces
ip -all netns delete

ip netns add tg
ip netns add sut

ip -netns tg link add enp6s0f0 type veth peer name enp6s0f0 netns sut
ip -netns tg link add enp6s0f1 type veth peer name enp6s0f1 netns sut

###################
#### Node: TG #####
###################
echo -e "\nNode: TG"

ip -netns tg link set dev lo up

ip -netns tg link set dev enp6s0f0 address 00:00:00:00:01:00
ip -netns tg link set dev enp6s0f1 address 00:00:00:00:01:01

ip -netns tg link set dev enp6s0f0 up
ip -netns tg link set dev enp6s0f1 up

ip -netns tg addr add 12:1::1/64 dev enp6s0f0
ip -netns tg addr add fc01::1/64 dev enp6s0f0
ip -netns tg addr add fc02::1/64 dev enp6s0f0
ip -netns tg addr add 10.12.1.1/24 dev enp6s0f0

ip -netns tg addr add 12:2::1/64 dev enp6s0f1
ip -netns tg addr add 10.12.2.1/24 dev enp6s0f1

ip -netns tg -6 neigh add 12:1::2 lladdr 00:00:00:00:02:00 dev enp6s0f0
ip -netns tg -6 neigh add fc00::2 lladdr 00:00:00:00:02:00 dev enp6s0f0
ip -netns tg -6 neigh add fc02::2 lladdr 00:00:00:00:02:00 dev enp6s0f0

ip -netns tg -6 neigh add 12:2::2 lladdr 00:00:00:00:02:01 dev enp6s0f1

read -r -d '' tg_env <<-EOF
	# Everything that is private to the bash process that will be launch
	# mount the bpf filesystem.
	# Note: childs of the launching (parent) bash can access this instance
	# of the bpf filesystem. If you need to get access to the bpf filesystem
	# (where maps are available), you need to use nsenter with -m and -t
	# that points to the pid of the parent process (launching bash).
	# mount -t bpf bpf /sys/fs/bpf/
	# mount -t tracefs nodev /sys/kernel/tracing

	# It allows to load maps with many entries without failing
	# ulimit -l unlimited

	/bin/bash
EOF

####################
#### Node: SUT #####
####################
echo -e "\nNode: SUT"
ip netns exec sut sysctl -w net.ipv4.ip_forward=1
ip netns exec sut sysctl -w net.ipv6.conf.all.forwarding=1

ip -netns sut link set dev lo up

ip -netns sut link set dev enp6s0f0 address 00:00:00:00:02:00
ip -netns sut link set dev enp6s0f1 address 00:00:00:00:02:01

ip -netns sut link set dev enp6s0f0 up
ip -netns sut link set dev enp6s0f1 up

ip -netns sut addr add 12:1::2/64 dev enp6s0f0
ip -netns sut addr add fc01::2/64 dev enp6s0f0
ip -netns sut addr add fc02::2/64 dev enp6s0f0
ip -netns sut addr add 10.12.1.2/24 dev enp6s0f0

ip -netns sut addr add 12:2::2/64 dev enp6s0f1
ip -netns sut addr add 10.12.2.2/24 dev enp6s0f1

ip -netns sut -6 neigh add 12:1::1 lladdr 00:00:00:00:01:00 dev enp6s0f0
ip -netns sut -6 neigh add fc00::1 lladdr 00:00:00:00:01:00 dev enp6s0f0
ip -netns sut -6 neigh add fc02::1 lladdr 00:00:00:00:01:00 dev enp6s0f0

ip -netns sut -6 neigh add 12:2::1 lladdr 00:00:00:00:01:01 dev enp6s0f1

export HIKECC="../hike-tools/hikecc.sh"

read -r -d '' sut_env <<-EOF
	# Everything that is private to the bash process that will be launch
	# mount the bpf filesystem.
	# Note: childs of the launching (parent) bash can access this instance
	# of the bpf filesystem. If you need to get access to the bpf filesystem
	# (where maps are available), you need to use nsenter with -m and -t
	# that points to the pid of the parent process (launching bash).

	mount -t bpf bpf /sys/fs/bpf/
	mount -t tracefs nodev /sys/kernel/tracing

	# It allows to load maps with many entries without failing
	ulimit -l unlimited

	mkdir -p /sys/fs/bpf/{maps,progs}

	# Load all the classifiers
	# ========================

	bpftool prog loadall raw_ddos_mmrt.o /sys/fs/bpf/progs/rawddos type xdp \
		pinmaps /sys/fs/bpf/maps/rawddos

	bpftool prog loadall raw_pass.o /sys/fs/bpf/progs/rpass type xdp \
		pinmaps /sys/fs/bpf/maps/rpass

	# Populate the jmp map (for tail calls)
	# =====================================

	bpftool map update pinned /sys/fs/bpf/maps/rawddos/raw_jmp_map 	\
		key	hex 01 00 00 00					\
		value	pinned /sys/fs/bpf/progs/rawddos/raw_ipv6_set_ecn

	bpftool map update pinned /sys/fs/bpf/maps/rawddos/raw_jmp_map 	\
		key	hex 02 00 00 00					\
		value	pinned /sys/fs/bpf/progs/rawddos/raw_mon_ecn_event

	bpftool map update pinned /sys/fs/bpf/maps/rawddos/raw_jmp_map 	\
		key	hex 03 00 00 00					\
		value	pinned /sys/fs/bpf/progs/rawddos/raw_ipv6_kroute

	# Attach loader and raw pass program
	# ==================================

	# Attach the (pinned) classifier to the netdev enp6s0f0 on the XDP hook.
	bpftool net attach xdpdrv 					\
		pinned /sys/fs/bpf/progs/rawddos/raw_classifier dev enp6s0f0

	# Attach dummy xdp pass program to the netdev enp6s0f1 XDP hook.
	bpftool net attach xdpdrv 					\
		pinned /sys/fs/bpf/progs/rpass/xdp_pass dev enp6s0f1

	# Loader/Classifier configuration
	# ===============================

	# Load the ddos classifier map config for IPv6 addresses
	bpftool map update pinned /sys/fs/bpf/maps/rawddos/map_ipv6		\
		key hex		00 12 00 01 00 00 00 00 00 00 00 00 00 00 00 02 \
		value hex 	01 00 00 00

	/bin/bash
EOF

###

## Create a new tmux session
sleep 1

tmux new-session -d -s $TMUX -n TG ip netns exec tg bash -c "${tg_env}"
tmux new-window -t $TMUX -n SUT ip netns exec sut bash -c "${sut_env}"

tmux select-window -t :1
tmux set-option -g mouse on
tmux attach -t $TMUX
