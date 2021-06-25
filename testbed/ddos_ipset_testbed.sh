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
ip -netns tg addr add fc01::1/64 dev enp6s0f0
ip -netns tg addr add fc02::1/64 dev enp6s0f0
ip -netns tg addr add 10.12.1.1/24 dev enp6s0f0

ip -netns tg addr add 12:2::1/64 dev enp6s0f1
ip -netns tg addr add 10.12.2.1/24 dev enp6s0f1



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


#ipset
ip netns exec sut ip6tables -N mark-ch -t mangle
ip netns exec sut ip6tables -A PREROUTING -t mangle -i enp6s0f0 -j mark-ch
ip netns exec sut ipset -N mark-ht hash:ip family inet6 counters
ip netns exec sut ipset -A mark-ht 12:1::2
ip netns exec sut ip6tables -A mark-ch -t mangle -m set --match-set mark-ht dst -j TOS --set-tos 0x01


## Create a new tmux session
sleep 1

tmux new-session -d -s $TMUX -n TG ip netns exec tg bash 
tmux new-window -t $TMUX -n SUT ip netns exec sut bash

tmux select-window -t :1
tmux set-option -g mouse on
tmux attach -t $TMUX
