#!/bin/sh

set -eu

NS=eskep

if [ "$(id -u)" -ne 0 ]; then
	echo "setup: run as root" >&2
	exit 1
fi

if [ -z "${PWNESC_INNER:-}" ]; then
	ip netns add "$NS" 2>/dev/null || true
	exec ip netns exec "$NS" env PWNESC_INNER=1 "$0"
fi

if ! ip link show pwntap >/dev/null 2>&1; then
	ip tuntap add dev pwntap mode tap
fi
ip link set pwntap address 02:00:00:00:00:01
ip link set pwntap up
ip link set pwntap promisc on
ip addr replace 10.0.0.1/24 dev pwntap

if ! ip link show pwnv0 >/dev/null 2>&1; then
	ip link add pwnv0 type veth peer name pwnv1
fi
ip link set pwnv0 mtu 200
ip link set pwnv0 up
ip link set pwnv1 up
ip addr replace 10.99.0.1/24 dev pwnv0
ip neigh replace 10.99.0.2 lladdr "$(cat /sys/class/net/pwnv1/address)" dev pwnv0 nud permanent

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.pwntap.rp_filter=0
sysctl -w net.ipv4.conf.pwnv0.rp_filter=0

if ! nft list table ip pwn >/dev/null 2>&1; then
	nft add table ip pwn
	nft add chain ip pwn pre '{ type filter hook prerouting priority -450; policy accept; }'
	nft add rule ip pwn pre ct state new accept
fi

echo "ready"
