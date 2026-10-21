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
