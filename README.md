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
the original experimental protocol carrier. `-dst-mac`, `-gateway`, and `-src`
can be used when automatic discovery is unavailable.

Repeated egress samples are sent as one batch and share a single capture window:

```sh
./test -egress -count 100 -egress-wait-ms 10000
```

For a controlled external endpoint, `cmd/receiver` passively records the same
mutated packets before the endpoint's IP stack handles them. It does not supply
checksum-offload metadata and therefore does not exercise this vulnerability on
the collector host:

```sh
go build -o receiver ./cmd/receiver
sudo ./receiver -iface eth0 -udp-port 9
```

The local TAP/netns lab can also test other deferred mutations with
`-csum-offset` (any byte offset in the IPv4 header or first-fragment payload)
and `-csum-word` (the host-endian 16-bit value to write, except the unattainable
one's-complement value `0xffff`). The default `0/0x004f` remains the verified
IHL disclosure. The fragmenter subsequently replaces the total-length,
fragment-offset, and header-checksum bytes at offsets 2..3, 6..7, and 10..11;
the probe verifies any surviving byte of an overlapping unaligned write and
reports fully transient writes for kernel tracing or KASAN.
