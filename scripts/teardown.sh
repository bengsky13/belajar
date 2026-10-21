#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
	echo "teardown: run as root from the host namespace, not from inside pwnesc" >&2
	exit 1
fi

if [ -n "${PWNESC_INNER:-}" ]; then
	echo "teardown: run this from the host, after leaving the netns shell" >&2
	exit 1
fi

ip netns del pwnesc 2>/dev/null || true
echo "removed"
