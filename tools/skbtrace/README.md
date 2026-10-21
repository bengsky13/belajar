# skbtrace

This is a bounded CO-RE tracer for the disposable local PwnEscape lab. It
uses raw `net_dev_queue` and `net_dev_start_xmit` tracepoints to record the
`sk_buff` geometry and bytes around the logical linear tail without modifying
kernel memory. Raw tracepoints avoid restricted fentry and unavailable
kprobe-multi interfaces in the target guest.

Build and run on the Linux guest:

```sh
clang -target bpf -D__TARGET_ARCH_x86 -O2 -g -c bpf/trace.bpf.c -o trace.bpf.o
GOTOOLCHAIN=local go mod tidy
GOTOOLCHAIN=local go build -o skbtrace .
sudo ./skbtrace -duration 30s
```
