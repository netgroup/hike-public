#!/bin/bash

#                     +------------------+      +------------------+
#                     |        TG        |      |       SUT        |
#                     |                  |      |                  |
#                     |         enp6s0f0 +------+ enp6s0f0 <--- HIKe VM XDP loader
#                     |                  |      |                  |
#                     |                  |      |                  |
#                     |         enp6s0f1 +------+ enp6s0f1         |
#                     |                  |      |         + cl0  <-|- towards the collector
#                     +------------------+      +---------|--------+
#                                                         |
#                                                         |
#                                               +---------|------+
#                                               |         + eth0 |
#                                               |                |
#                                               |    COLLECTOR   |
#                                               +----------------+



TMUX=ebpf
IPP=ip

# Kill tmux previous session
tmux kill-session -t $TMUX 2>/dev/null

# Clean up previous network namespaces
ip -all netns delete

ip netns add tg
ip netns add sut
ip netns add clt

ip -netns tg link add enp6s0f0 type veth peer name enp6s0f0 netns sut
ip -netns tg link add enp6s0f1 type veth peer name enp6s0f1 netns sut

ip -netns sut link add cl0 type veth peer name veth0 netns clt

export HIKECC="../hike-tools/hikecc.sh"; readonly HIKECC
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

# --- SRv6 ---
# ============
ip -netns tg addr add db8::1/128 dev enp6s0f0

ip -netns tg -6 route add db8::2 encap seg6 \
	mode inline segs fa00::2 dev enp6s0f0

ip -netns tg -6 route add fa00::1 encap seg6local \
	action End.DT6 table local dev enp6s0f0

ip -netns tg -6 route add fa00::2 via fc01::2 dev enp6s0f0
# ---

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

# Sink interface (dummy)
ip -netns sut link set dev cl0 up
ip -netns sut addr add cafe::1/64 dev cl0

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

# --- SRv6 ---
# ============
ip -netns sut addr add db8::2/128 dev enp6s0f0

ip -netns sut -6 route add db8::1 encap seg6 \
	mode encap segs fa00::1 dev enp6s0f0

ip -netns sut -6 route add fa00::2 encap seg6local \
	action End.DT6 table local dev enp6s0f0

ip -netns sut -6 route add fa00::1 via fc01::1 dev enp6s0f0
# ---

read -r -d '' sut_env <<-EOF
	# Everything that is private to the bash process that will be launched
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
	mkdir -p /sys/fs/bpf/{progs,maps}

	# It allows to load maps with many entries without failing
	ulimit -l unlimited

	# Load the classifier (or the chain bootloader)
	mkdir -p /sys/fs/bpf/{progs/init,maps/init}
	${BPFTOOL} prog loadall ip6_simple_classifier.o /sys/fs/bpf/progs/init \
		type xdp \
		pinmaps /sys/fs/bpf/maps/init

	# Load all the progs contained into net.o and pin them on the bpffs.
	# All HIKe programs *.o must reuse the maps that have been
	# already created and pinned by the classifier. Indeed, we specify
	# the maps that have to be re-bound to programs contained in *.o
	#
	# MAP RE-BIND IS VERY IMPORTANT, OTHERWISE PROGRAMS WILL HAVE A COPY
	# OF THE SAME MAPS AND THEY WILL NOT BE ABLE TO COMMUNICATE WITH EACH
	# OTHER!! THAT'S A VERY SUBTLE ISSUE TO FIX UP!


	mkdir -p /sys/fs/bpf/{progs/ipv6_hset_srcdst,maps/ipv6_hset_srcdst}
	${BPFTOOL} prog loadall ip6_hset_srcdst.o /sys/fs/bpf/progs/ipv6_hset_srcdst \
		type xdp						\
		map name hvm_hprog_map					\
			pinned	/sys/fs/bpf/maps/init/hvm_hprog_map	\
		map name hvm_chain_map					\
			pinned /sys/fs/bpf/maps/init/hvm_chain_map 	\
		map name hvm_cdata_map			\
			pinned /sys/fs/bpf/maps/init/hvm_cdata_map \
		map name hvm_shmem_map				\
			pinned /sys/fs/bpf/maps/init/hvm_shmem_map \
		pinmaps /sys/fs/bpf/maps/ipv6_hset_srcdst

	mkdir -p /sys/fs/bpf/{progs/hike_pass,maps/hike_pass}
	${BPFTOOL} prog loadall hike_pass.o /sys/fs/bpf/progs/hike_pass \
		type xdp						\
		map name hvm_hprog_map					\
			pinned	/sys/fs/bpf/maps/init/hvm_hprog_map	\
		map name hvm_chain_map					\
			pinned /sys/fs/bpf/maps/init/hvm_chain_map 	\
		map name hvm_cdata_map			\
			pinned /sys/fs/bpf/maps/init/hvm_cdata_map \
		map name hvm_shmem_map				\
			pinned /sys/fs/bpf/maps/init/hvm_shmem_map \
		pinmaps /sys/fs/bpf/maps/hike_pass

	mkdir -p /sys/fs/bpf/{progs/hike_drop,maps/hike_drop}
	${BPFTOOL} prog loadall hike_drop.o /sys/fs/bpf/progs/hike_drop \
		type xdp						\
		map name hvm_hprog_map					\
			pinned	/sys/fs/bpf/maps/init/hvm_hprog_map	\
		map name hvm_chain_map					\
			pinned /sys/fs/bpf/maps/init/hvm_chain_map 	\
		map name hvm_cdata_map			\
			pinned /sys/fs/bpf/maps/init/hvm_cdata_map \
		map name hvm_shmem_map				\
			pinned /sys/fs/bpf/maps/init/hvm_shmem_map \
		pinmaps /sys/fs/bpf/maps/hike_drop

	mkdir -p /sys/fs/bpf/{progs/mon,maps/mon}
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

	mkdir -p /sys/fs/bpf/{progs/lse,maps/lse}
	${BPFTOOL} prog loadall lastevent.o /sys/fs/bpf/progs/lse type xdp	\
		map name hvm_hprog_map					\
			pinned	/sys/fs/bpf/maps/init/hvm_hprog_map	\
		map name hvm_chain_map					\
			pinned /sys/fs/bpf/maps/init/hvm_chain_map 	\
		map name hvm_cdata_map			\
			pinned /sys/fs/bpf/maps/init/hvm_cdata_map \
		map name hvm_shmem_map				\
			pinned /sys/fs/bpf/maps/init/hvm_shmem_map \
		pinmaps /sys/fs/bpf/maps/lse

	mkdir -p /sys/fs/bpf/{progs/l2red,maps/l2red}
	${BPFTOOL} prog loadall l2red.o /sys/fs/bpf/progs/l2red type xdp \
		map name hvm_hprog_map					\
			pinned	/sys/fs/bpf/maps/init/hvm_hprog_map	\
		map name hvm_chain_map					\
			pinned /sys/fs/bpf/maps/init/hvm_chain_map 	\
		map name hvm_cdata_map			\
			pinned /sys/fs/bpf/maps/init/hvm_cdata_map \
		map name hvm_shmem_map				\
			pinned /sys/fs/bpf/maps/init/hvm_shmem_map \
		pinmaps /sys/fs/bpf/maps/l2red

	mkdir -p /sys/fs/bpf/{progs/appcfg,maps/appcfg}
	${BPFTOOL} prog loadall app_cfg.o /sys/fs/bpf/progs/appcfg type xdp \
		map name hvm_hprog_map					\
			pinned	/sys/fs/bpf/maps/init/hvm_hprog_map	\
		map name hvm_chain_map					\
			pinned /sys/fs/bpf/maps/init/hvm_chain_map 	\
		map name hvm_cdata_map			\
			pinned /sys/fs/bpf/maps/init/hvm_cdata_map \
		map name hvm_shmem_map				\
			pinned /sys/fs/bpf/maps/init/hvm_shmem_map \
		pinmaps /sys/fs/bpf/maps/appcfg

	${BPFTOOL} prog loadall app_cfg_load.o /sys/fs/bpf/progs/appcfg type xdp \
		map name hvm_hprog_map					\
			pinned	/sys/fs/bpf/maps/init/hvm_hprog_map	\
		map name hvm_chain_map					\
			pinned /sys/fs/bpf/maps/init/hvm_chain_map 	\
		map name hvm_cdata_map					\
			pinned /sys/fs/bpf/maps/init/hvm_cdata_map	\
		map name hvm_shmem_map					\
			pinned /sys/fs/bpf/maps/init/hvm_shmem_map	\
		map name map_app_cfg					\
			pinned /sys/fs/bpf/maps/appcfg/map_app_cfg

	mkdir -p /sys/fs/bpf/{progs/ip6_fndudp,maps/ip6_fndudp}
	${BPFTOOL} prog loadall ip6_find_udp.o /sys/fs/bpf/progs/ip6_fndudp type xdp \
		map name hvm_hprog_map					\
			pinned	/sys/fs/bpf/maps/init/hvm_hprog_map	\
		map name hvm_chain_map					\
			pinned /sys/fs/bpf/maps/init/hvm_chain_map 	\
		map name hvm_cdata_map			\
			pinned /sys/fs/bpf/maps/init/hvm_cdata_map \
		map name hvm_shmem_map				\
			pinned /sys/fs/bpf/maps/init/hvm_shmem_map \
		pinmaps /sys/fs/bpf/maps/ip6_fndudp

	mkdir -p /sys/fs/bpf/{progs/hike_verb,maps/hike_verb}
	${BPFTOOL} prog loadall hike_verbose.o /sys/fs/bpf/progs/hike_verb type xdp \
		map name hvm_hprog_map					\
			pinned	/sys/fs/bpf/maps/init/hvm_hprog_map	\
		map name hvm_chain_map					\
			pinned /sys/fs/bpf/maps/init/hvm_chain_map 	\
		map name hvm_cdata_map			\
			pinned /sys/fs/bpf/maps/init/hvm_cdata_map \
		map name hvm_shmem_map				\
			pinned /sys/fs/bpf/maps/init/hvm_shmem_map \
		pinmaps /sys/fs/bpf/maps/hike_verb

	mkdir -p /sys/fs/bpf/{progs/sr6_inline_udp,maps/sr6_inline_udp}
	${BPFTOOL} prog loadall sr6_inline_udp.o /sys/fs/bpf/progs/sr6_inline_udp type xdp \
		map name hvm_hprog_map					\
			pinned	/sys/fs/bpf/maps/init/hvm_hprog_map	\
		map name hvm_chain_map					\
			pinned /sys/fs/bpf/maps/init/hvm_chain_map 	\
		map name hvm_cdata_map			\
			pinned /sys/fs/bpf/maps/init/hvm_cdata_map \
		map name hvm_shmem_map				\
			pinned /sys/fs/bpf/maps/init/hvm_shmem_map \
		pinmaps /sys/fs/bpf/maps/sr6_inline_udp

	# NOT an HIKe eBPF Program
	mkdir -p /sys/fs/bpf/{progs/rawpass,}
	${BPFTOOL} prog loadall raw_pass.o /sys/fs/bpf/progs/rawpass type xdp

	# =================================================================== #

	# Attach the (pinned) classifier to the netdev enp6s0f0 on the XDP hook.
	${BPFTOOL} net attach xdpdrv 					\
		pinned /sys/fs/bpf/progs/init/ipv6_simple_classifier 	\
		dev enp6s0f0

        # Attach the (pinned) raw_pass program to netdev enp6s0f1 on the
	# XDP hook.
        ${BPFTOOL} net attach xdpdrv                               \
                pinned /sys/fs/bpf/progs/rawpass/xdp_pass       \
                dev enp6s0f1

	# Attach the (pinned) raw_pass program to netdev cl0 on the
	# XDP hook.
	${BPFTOOL} net attach xdpdrv 				\
		pinned /sys/fs/bpf/progs/rawpass/xdp_pass	\
                dev cl0

	# Jump Map configuration (used for carring out tail calls in HIKe VM)
	# Let's populate the hvm_hprog_map so that we can perform tail calls!

	# Register allow_any eBPF/HIKe Program
	# Prog ID is defined in minimal.h; we need to parse that file and
	# use the macro value here... but I'm lazy... are YOU brave enough
	# to do that? :-)

	${BPFTOOL} map update pinned /sys/fs/bpf/maps/init/hvm_hprog_map 	\
		key	hex 1b 00 00 00					\
		value	pinned /sys/fs/bpf/progs/ipv6_hset_srcdst/hvxdp_ipv6_hset_srcdst

	${BPFTOOL} map update pinned /sys/fs/bpf/maps/init/hvm_hprog_map 	\
		key	hex 1c 00 00 00					\
		value	pinned /sys/fs/bpf/progs/hike_pass/hvxdp_hike_pass

	${BPFTOOL} map update pinned /sys/fs/bpf/maps/init/hvm_hprog_map 	\
		key	hex 1d 00 00 00					\
		value	pinned /sys/fs/bpf/progs/hike_drop/hvxdp_hike_drop

	${BPFTOOL} map update pinned /sys/fs/bpf/maps/init/hvm_hprog_map 	\
		key	hex 1e 00 00 00					\
		value	pinned /sys/fs/bpf/progs/lse/hvxdp_pcpu_lse

	${BPFTOOL} map update pinned /sys/fs/bpf/maps/init/hvm_hprog_map 	\
		key	hex 0e 00 00 00					\
		value	pinned /sys/fs/bpf/progs/mon/hvxdp_pcpu_mon

	${BPFTOOL} map update pinned /sys/fs/bpf/maps/init/hvm_hprog_map 	\
		key	hex 1f 00 00 00					\
		value	pinned /sys/fs/bpf/progs/l2red/hvxdp_l2_redirect

	${BPFTOOL} map update pinned /sys/fs/bpf/maps/init/hvm_hprog_map 	\
		key	hex 11 00 00 00					\
		value	pinned /sys/fs/bpf/progs/appcfg/hvxdp_app_cfg_load

	${BPFTOOL} map update pinned /sys/fs/bpf/maps/init/hvm_hprog_map 	\
		key	hex 20 00 00 00					\
		value	pinned /sys/fs/bpf/progs/ip6_fndudp/hvxdp_ipv6_find_udp

	${BPFTOOL} map update pinned /sys/fs/bpf/maps/init/hvm_hprog_map 	\
		key	hex 21 00 00 00					\
		value	pinned /sys/fs/bpf/progs/hike_verb/hvxdp_hike_verbose

	${BPFTOOL} map update pinned /sys/fs/bpf/maps/init/hvm_hprog_map 	\
		key	hex 22 00 00 00					\
		value	pinned /sys/fs/bpf/progs/sr6_inline_udp/hvxdp_sr6_inline_udp

	# =================================================================== #


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

	# Configure the Loader
	${BPFTOOL} map update \
		pinned /sys/fs/bpf/maps/init/ipv6_simple_classifier_map \
		key hex		00 00 00 00				\
		value hex 	59 00 00 40

	# Program the IPv6 <src,dst> hashset
	# ${BPFTOOL} map update \
	# 	pinned /sys/fs/bpf/maps/ipv6_hset_srcdst/ipv6_hset_srcdst_map   \
	# 	key hex		00 12 00 01 00 00 00 00 00 00 00 00 00 00 00 01 \
	# 			00 12 00 01 00 00 00 00 00 00 00 00 00 00 00 02 \
	# 	value hex	ab 00 00 00 00 00 00 00

	# Configure the appcfg by setting the Collector oif KEY (0x2) with the
	# supplied value (0x4 which is the SUT cl0 ifindex)
	${BPFTOOL} map update					\
		pinned /sys/fs/bpf/maps/appcfg/map_app_cfg	\
		key	hex	02 00 00 00			\
		value	hex	04 00 00 00

	/bin/bash
EOF

####################
#### Node: CLT #####
####################
echo -e "\nNode: CLT"
ip netns exec clt sysctl -w net.ipv4.ip_forward=1
ip netns exec clt sysctl -w net.ipv6.conf.all.forwarding=1

ip -netns clt link set dev lo up
ip -netns clt link set dev veth0 up

ip -netns clt addr add cafe::2/64 dev veth0

read -r -d '' clt_env <<-EOF
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

	mkdir -p /sys/fs/bpf/{progs,maps}
	# NOT an HIKe eBPF Program
	mkdir -p /sys/fs/bpf/{progs/rawpass,}
	${BPFTOOL} prog loadall raw_pass.o /sys/fs/bpf/progs/rawpass type xdp

	# Attach the (pinned) raw_pass program to netdev veth0 on the
	# XDP hook.
	${BPFTOOL} net attach xdpdrv 				\
		pinned /sys/fs/bpf/progs/rawpass/xdp_pass	\
                dev veth0

	/bin/bash
EOF

###

## Create a new tmux session
sleep 1

tmux new-session -d -s $TMUX -n TG ip netns exec tg bash -c "${tg_env}"
tmux new-window -t $TMUX -n SUT ip netns exec sut bash -c "${sut_env}"
tmux new-window -t $TMUX -n CLT ip netns exec clt bash -c "${clt_env}"

tmux select-window -t :1
tmux set-option -g mouse on
tmux attach -t $TMUX
