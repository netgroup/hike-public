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

export BPFTOOL="../tools/bpftool"; readonly BPFTOOL

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

	# With ${BPFTOOL} we cannot pin maps which have been already pinned
	# on the same bpffs. The same also applies to eBPF programs.
	# For this reason, we create {init,net} dirs in progs and
	# {init,net} in maps.
	#
	mkdir -p /sys/fs/bpf/progs/init
	mkdir -p /sys/fs/bpf/progs/net

	mkdir -p /sys/fs/bpf/maps/init
	mkdir -p /sys/fs/bpf/maps/net

	# It allows to load maps with many entries without failing
	ulimit -l unlimited

	# Load all the classifiers
	${BPFTOOL} prog loadall classifier.o /sys/fs/bpf/progs/init type xdp \
		pinmaps /sys/fs/bpf/maps/init

	# Load all the progs contained into net.o and pin them on the bpffs.
	# ALl programs contained in net.o must reuse the maps that have been
	# already created and pinned by the classifier. Indeed, we specify
	# the maps that have to be re-bound to programs contained in progs.o
	#
	# MAP RE-BIND IS VERY IMPORTANT, OTHERWISE PROGRAMS WILL HAVE A COPY
	# OF THE SAME MAPS AND THEY WILL NOT BE ABLE TO COMMUNICATE WITH EACH
	# OTHER!! THAT'S A VERY SUBTLE ISSUE TO FIX UP!
	#

	${BPFTOOL} prog loadall monitor.o /sys/fs/bpf/progs/mon type xdp	\
		map name hvm_hprog_map					\
			pinned	/sys/fs/bpf/maps/init/hvm_hprog_map	\
		map name hvm_chain_map					\
			pinned /sys/fs/bpf/maps/init/hvm_chain_map 	\
		map name hvm_cdata_map			\
			pinned /sys/fs/bpf/maps/init/hvm_cdata_map \
		map name hvm_shmem_map				\
			pinned /sys/fs/bpf/maps/init/hvm_shmem_map \
		pinmaps /sys/fs/bpf/maps/mon

	${BPFTOOL} prog loadall ip6_set_ecn.o /sys/fs/bpf/progs/ip6setecn type xdp \
		map name hvm_hprog_map					\
			pinned	/sys/fs/bpf/maps/init/hvm_hprog_map	\
		map name hvm_chain_map					\
			pinned /sys/fs/bpf/maps/init/hvm_chain_map 	\
		map name hvm_cdata_map			\
			pinned /sys/fs/bpf/maps/init/hvm_cdata_map \
		map name hvm_shmem_map				\
			pinned /sys/fs/bpf/maps/init/hvm_shmem_map \
		pinmaps /sys/fs/bpf/maps/ip6setecn

	${BPFTOOL} prog loadall ip6_kroute.o /sys/fs/bpf/progs/ip6krt type xdp \
		map name hvm_hprog_map					\
			pinned	/sys/fs/bpf/maps/init/hvm_hprog_map	\
		map name hvm_chain_map					\
			pinned /sys/fs/bpf/maps/init/hvm_chain_map 	\
		map name hvm_cdata_map			\
			pinned /sys/fs/bpf/maps/init/hvm_cdata_map \
		map name hvm_shmem_map				\
			pinned /sys/fs/bpf/maps/init/hvm_shmem_map \
		pinmaps /sys/fs/bpf/maps/ip6krt

	# Attach the (pinned) classifier to the netdev enp6s0f0 on the XDP hook.
	${BPFTOOL} net attach xdpdrv 					\
		pinned /sys/fs/bpf/progs/init/hike_classifier dev enp6s0f0

	${BPFTOOL} prog loadall raw_pass.o /sys/fs/bpf/progs/rpass type xdp \
		pinmaps /sys/fs/bpf/maps/rpass

	# Attach dummy xdp pass program to the netdev enp6s0f1 XDP hook.
	${BPFTOOL} net attach xdpdrv 					\
		pinned /sys/fs/bpf/progs/rpass/xdp_pass dev enp6s0f1

	# Jump Map configuration (used for carring out tail calls in HIKe VM)
	# Let's populate the hvm_hprog_map so that we can perform tail calls!

	# Register allow_any eBPF/HIKe Program
	# Prog ID is defined in minimal.h; we need to parse that file and
	# use the macro value here... but I'm lazy... are YOU brave enough
	# to do that? :-)

	# Register count packet eBPF/HIKe Program, please see description above ;-)
	${BPFTOOL} map update pinned /sys/fs/bpf/maps/init/hvm_hprog_map 	\
		key	hex 0e 00 00 00					\
		value	pinned /sys/fs/bpf/progs/mon/hvxdp_pcpu_mon

	# Register count packet eBPF/HIKe Program, please see description above ;-)
	${BPFTOOL} map update pinned /sys/fs/bpf/maps/init/hvm_hprog_map 	\
		key	hex 17 00 00 00					\
		value	pinned /sys/fs/bpf/progs/ip6setecn/hvxdp_ipv6_set_ecn

	# Register count packet eBPF/HIKe Program, please see description above ;-)
	${BPFTOOL} map update pinned /sys/fs/bpf/maps/init/hvm_hprog_map 	\
		key	hex 19 00 00 00					\
		value	pinned /sys/fs/bpf/progs/ip6krt/hvxdp_ipv6_kroute

	# HIKe Programs are now loaded, let's move on by loading the HIKe Chains.
	# First of all we build the HIKe Chain program loader using the
	# .hike.o object (which contains all the HIKe Chains defined so far).

	# The HIKECC takes as 1) the HIKe Chains object file; 2) the eBPF map
	# that contains all the HIKe Chains; 3) the path of the load script
	# that is going to be generated.

	${HIKECC} data/binaries/minimal_chain.hike.o			\
		  /sys/fs/bpf/maps/init/hvm_chain_map 			\
		  data/binaries/minimal_chain.hike.load.sh

	# Load HIKe Chains calling the loader script we just built :-o
	/bin/bash data/binaries/minimal_chain.hike.load.sh

	# Load the ddos classifier map config for IPv6 addresses
	${BPFTOOL} map update pinned /sys/fs/bpf/maps/init/map_ipv6		\
		key hex		00 12 00 01 00 00 00 00 00 00 00 00 00 00 00 02 \
		value hex 	54 00 00 40



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
