Belajar networking

The original TAP/netns reproducer remains the default mode. To carry the same
checksum metadata across a Firecracker guest's real virtio-net boundary, run as
root inside the guest:

```sh
./test -egress -iface eth0 -dst chall.itsbengsky.id
```

Egress mode resolves the IPv4 route and next-hop MAC, sends the completing
fragments before the short malicious head, and listens for an ICMP quotation of
the resulting protocol-253 datagram. `-dst-mac`, `-gateway`, and `-src` can be
used when automatic discovery is unavailable.
