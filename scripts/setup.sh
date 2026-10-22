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

if ! ip link show bengskytap >/dev/null 2>&1; then
	ip tuntap add dev bengskytap mode tap
fi
ip link set bengskytap address 02:00:00:00:00:01
ip link set bengskytap up
ip link set bengskytap promisc on
ip addr replace 10.0.0.1/24 dev bengskytap

if ! ip link show bengskyv0 >/dev/null 2>&1; then
	ip link add bengskyv0 type veth peer name bengskyv1
fi
ip link set bengskyv0 mtu 200
ip link set bengskyv0 up
ip link set bengskyv1 up
ip addr replace 10.99.0.1/24 dev bengskyv0
ip neigh replace 10.99.0.2 lladdr "$(cat /sys/class/net/bengskyv1/address)" dev bengskyv0 nud permanent

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.bengskytap.rp_filter=0
sysctl -w net.ipv4.conf.bengskyv0.rp_filter=0
# The high-order PCP priming probe deliberately holds incomplete anchor
# queues while a large local batch is allocated and released under TCG.
sysctl -w net.ipv4.ipfrag_time=120
sysctl -w net.ipv4.ipfrag_max_dist=0

if ! nft list table ip pwn >/dev/null 2>&1; then
	nft add table ip pwn
	nft add chain ip pwn pre '{ type filter hook prerouting priority -450; policy accept; }'
	nft add rule ip pwn pre ct state new accept
fi

# The disposable local-reassembly probe needs to bypass conntrack defrag so
# IPv4's LOCAL_DELIVER queue reaches skb_try_coalesce. This matches only the
# lab's protocol-252/253 traffic addressed to the TAP itself. Protocol 252 is
# reserved here for the same-CPU PCP priming queue.
if ! nft list chain ip pwn local_raw >/dev/null 2>&1; then
	nft add chain ip pwn local_raw '{ type filter hook prerouting priority -500; policy accept; }'
fi
if ! nft list chain ip pwn local_raw | grep -q 'ip daddr 10.0.0.1 meta l4proto 253 notrack'; then
	nft add rule ip pwn local_raw ip daddr 10.0.0.1 meta l4proto 253 notrack
fi
if ! nft list chain ip pwn local_raw | grep -q 'ip daddr 10.0.0.1 meta l4proto 252 notrack'; then
	nft add rule ip pwn local_raw ip daddr 10.0.0.1 meta l4proto 252 notrack
fi

echo "ready"
