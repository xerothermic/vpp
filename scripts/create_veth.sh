#!/bin/bash

sudo ip link add name vpp1out type veth peer name vpp1host

sudo ip link set dev vpp1out up
sudo ip link set dev vpp1host up

sudo ip addr add 1.1.1.1/24 dev vpp1host
ip link
ip addr show vpp1host