#!/bin/bash

#                     +------------------+      +------------------+
#                     |        TG        |      |       SUT        |
#                     |                  |      |                  |
#                     |         enp6s0f0 +------+ enp6s0f0         |
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
ip netns add lgs

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
ip -netns tg addr add 10.12.1.1/24 dev enp6s0f0

ip -netns tg addr add 12:2::1/64 dev enp6s0f1
ip -netns tg addr add 10.12.2.1/24 dev enp6s0f1

read -r -d '' tg_env <<-EOF
	# Everything that is private to the bash process that will be launch
	# mount the bpf filesystem.
	# Note: childs of the launching (parent) bash can access this instance
	# of the bpf filesystem. If you need to get access to the bpf filesystem
	# (where maps are available), you need to use nsenter with -m and -t
	# that points to the pid of the parent process (launching bash).

	mount -t bpf bpf /sys/fs/bpf/
	mount -t tracefs nodev /sys/kernel/tracing

	mkdir /sys/fs/bpf/progs
	mkdir /sys/fs/bpf/maps

	# It allows to load maps with many entries without failing
	ulimit -l unlimited
	
	# Load all the progs contained into prog.o and pin them into
	# progs bpffs. We also pin all the maps on maps bpffs.
	bpftool prog loadall prog.o /sys/fs/bpf/progs type xdp 		\
		pinmaps /sys/fs/bpf/maps

	# Attach the program xdp_root (pinned) to the netdev enp6s0f0 on the
	# XDP hook.
	bpftool net attach xdpdrv 					\
		pinned /sys/fs/bpf/progs/xdp_root dev enp6s0f0

	# Let's populate the jmp_table so that we can perform tail calls!
	bpftool map update pinned /sys/fs/bpf/maps/jmp_table 		\
		key	hex 01 00 00 00					\
		value	pinned /sys/fs/bpf/progs/xdp_root

	bpftool map update pinned /sys/fs/bpf/maps/jmp_table 		\
		key	hex 02 00 00 00					\
		value	pinned /sys/fs/bpf/progs/xdp_2

	# xdp_3 can replace program xdp_2
	# Note that we are using the key 0x02 for overwriting the program.
	bpftool map update pinned /sys/fs/bpf/maps/jmp_table		\
		key	hex 02 00 00 00					\
		value	pinned /sys/fs/bpf/progs/xdp_3

	# We unload the prog xdp_2 which is not useful anymore.
	# Because the only reference to this program is through the fs,
	# is enough to remove the link on the fs.
	rm /sys/fs/bpf/progs/xdp_2

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
ip -netns sut addr add 10.12.1.2/24 dev enp6s0f0

ip -netns sut addr add 12:2::2/64 dev enp6s0f1
ip -netns sut addr add 10.12.2.2/24 dev enp6s0f1


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

	# CODE HERE

	/bin/bash
EOF

## Create a new tmux session
sleep 1

tmux new-session -d -s $TMUX -n TG ip netns exec tg bash -c "${tg_env}"
tmux new-window -t $TMUX -n SUT ip netns exec sut bash -c "${sut_env}"

tmux select-window -t :0
tmux set-option -g mouse on
tmux attach -t $TMUX
