# this script is included in other testbed startup scripts
#
# topology:
#
#   +--------------+   +--------------+   +--------------+
#   |      h1      |   |       r2     |   |      h3      |
#   |              |   |              |   |              |
#   |          i12 +---+ i21      i23 +---+ i32      i34 |
#   |              |   |              |   |              |
#   |              |   |              |   |              |
#   +--------------+   +--------------+   +--------------+
#
# addresses:
# fd00::/8  <-  customers IPv6 networks
#
# 10.0.0.0/8  <-  customers IPv4 networks
#
# h1 i12 fd12::1/64 mac 00:00:00:00:01:02 IPv4 10.12.0.1/24
#
# r2 i21 fd12::2/64 mac 00:00:00:00:02:01 IPv4 10.12.0.2/24
# r2 i23 fd23::1/64 mac 00:00:00:00:02:03 IPv4 10.23.0.1/2
#
# h3 i32 fd23::2/64 mac 00:00:00:00:03:02 IPv4 10.23.0.2/24
#

TMUX=ebpf

# Kill tmux previous session
tmux kill-session -t $TMUX 2>/dev/null

# Clean up previous network namespaces
ip -all netns delete

ip netns add h1
ip netns add r2
ip netns add h3

ip -netns h1 link add i12 type veth peer name i21 netns r2
ip -netns r2 link add i23 type veth peer name i32 netns h3

export HIKECC="../hike-tools/hikecc.sh"; readonly HIKECC
export BPFTOOL="../tools/bpftool"; readonly BPFTOOL

###################
#### Node: h1 #####
###################
NODE=h1
echo -e "\nNode: $NODE"

ip -netns $NODE link set dev i12 address 00:00:00:00:01:02

ip -netns $NODE link set dev lo up
ip -netns $NODE link set dev i12 up

ip -netns $NODE addr add fd12::1/64 dev i12
ip -netns $NODE addr add 10.12.0.1/24 dev i12

ip -netns $NODE -6 neigh add fd12::2   lladdr 00:00:00:00:02:01 dev i12
ip -netns $NODE -4 neigh add 10.12.0.2 lladdr 00:00:00:00:02:01 dev i12

ip -netns $NODE -6 route add default via fd12::2 dev i12
ip -netns $NODE -4 route add default via 10.12.0.2 dev i12

read -r -d '' ${NODE}_env <<-EOF
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

###################
#### Node: r2 #####
###################
NODE=r2
echo -e "\nNode: $NODE"

ip -netns $NODE link set dev i21 address 00:00:00:00:02:01
ip -netns $NODE link set dev i23 address 00:00:00:00:02:03

ip -netns $NODE link set dev lo up
ip -netns $NODE link set dev i21 up
ip -netns $NODE link set dev i23 up

ip -netns $NODE addr add fd12::2/64 dev i21
ip -netns $NODE addr add fd23::1/64 dev i23

ip -netns $NODE addr add 10.12.0.2/24 dev i21
ip -netns $NODE addr add 10.23.0.1/24 dev i23

ip -netns $NODE -6 neigh add fd12::1   lladdr 00:00:00:00:01:02 dev i21
ip -netns $NODE -6 neigh add fd23::2   lladdr 00:00:00:00:03:02 dev i23

ip -netns $NODE -4 neigh add 10.12.0.1 lladdr 00:00:00:00:01:02 dev i21
ip -netns $NODE -4 neigh add 10.23.0.2 lladdr 00:00:00:00:03:02 dev i23

read -r -d '' ${NODE}_env <<-EOF
	echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
        echo 1 > /proc/sys/net/ipv4/ip_forward

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
	mkdir -p /sys/fs/bpf/{progs,maps}

	# Load all the classifiers
	# ========================

	${BPFTOOL} prog loadall \
		raw_ip6_fwdacc.o /sys/fs/bpf/progs/ip6fwdacc \
		type xdp \
		pinmaps /sys/fs/bpf/maps/ip6fwdacc

	${BPFTOOL} prog loadall \
		raw_pass.o /sys/fs/bpf/progs/rpass \
		type xdp \
		pinmaps /sys/fs/bpf/maps/rpass

	# Attach loader and raw pass program
	# ==================================

	# Attach the (pinned) classifier to the netdev i21 on the XDP hook.
	${BPFTOOL} net attach xdpdrv	\
		pinned /sys/fs/bpf/progs/ip6fwdacc/raw_ip6_fwdacc dev i21

	# Attach dummy xdp pass program to the netdev enp6s0f1 XDP hook.
	${BPFTOOL} net attach xdpdrv	\
		pinned /sys/fs/bpf/progs/rpass/xdp_pass dev i23

	# Configure the map for packet forwarding
	# =======================================

	# Load the classifier map config for IPv6 addresses
	${BPFTOOL} map update pinned /sys/fs/bpf/maps/ip6fwdacc/ip6_fwd_map \
		key hex		fd 23 00 00 00 00 00 00 00 00 00 00 00 00 00 02 \
		value hex	03 00 00 00 \
				00 00 00 00 03 02 \
				00 00 00 00 02 03

	/bin/bash
EOF

###################
#### Node: h3 #####
###################
NODE=h3
echo -e "\nNode: $NODE"

ip -netns $NODE link set dev i32 address 00:00:00:00:03:02

ip -netns $NODE link set dev lo up
ip -netns $NODE link set dev i32 up

ip -netns $NODE addr add fd23::2/64 dev i32
ip -netns $NODE addr add 10.23.0.2/24 dev i32

ip -netns $NODE -6 neigh add fd23::1 lladdr 00:00:00:00:02:03 dev i32
ip -netns $NODE -4 neigh add 10.23.0.1 lladdr 00:00:00:00:02:03 dev i32

ip -netns $NODE -6 route add default via fd23::1 dev i32
ip -netns $NODE -4 route add default via 10.23.0.1 dev i32


read -r -d '' ${NODE}_env <<-EOF
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
	mkdir -p /sys/fs/bpf/{progs,maps}

	# It allows to load maps with many entries without failing
	ulimit -l unlimited

	# Attach dummy xdp pass program to the netdev i32 XDP hook.
	${BPFTOOL} prog loadall raw_pass.o /sys/fs/bpf/progs/rpass	\
		type xdp \
		pinmaps /sys/fs/bpf/maps/rpass

	${BPFTOOL} net attach xdpdrv	\
		pinned /sys/fs/bpf/progs/rpass/xdp_pass dev i32

	/bin/bash
EOF

## Create a new tmux session
sleep 1

tmux new-session -d -s $TMUX -n MAIN bash
tmux new-window -t $TMUX -n H1 ip netns exec h1 bash -c "${h1_env}"
tmux new-window -t $TMUX -n R2 ip netns exec r2 bash -c "${r2_env}"
tmux new-window -t $TMUX -n H3 ip netns exec h3 bash -c "${h3_env}"

tmux select-window -t $TMUX:R2
tmux set-option -g mouse on
tmux attach -t $TMUX
