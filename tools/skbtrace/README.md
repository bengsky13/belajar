# skbtrace

This is a bounded CO-RE tracer for the disposable local PwnEscape lab. It
uses kprobe-multi links to record the `sk_buff` geometry and bytes around the
logical linear tail at `ip_do_fragment()` and `skb_checksum_help()` without
modifying kernel memory. Kprobe-multi avoids the tracefs `kprobe_events` file,
which may be unavailable in a restricted guest.

Build and run on the Linux guest:

```sh
clang -target bpf -D__TARGET_ARCH_x86 -O2 -g -c bpf/trace.bpf.c -o trace.bpf.o
GOTOOLCHAIN=local go mod tidy
GOTOOLCHAIN=local go build -o skbtrace .
sudo ./skbtrace -duration 30s
```
