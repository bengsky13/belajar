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

Each raw-tracepoint event reports the current task-fragment page `_refcount`,
which makes before/after page-release comparisons possible even when the
kernel inlines `put_page`.  In the disposable lab only, `-put-page` also
attaches a `put_page` kprobe and prints calls that reach the out-of-line symbol.
The raw tracepoint collector remains the default because the hosted guest may
deny kprobes.

`-coalesce` is also disposable-lab-only. It attaches entry and return probes
to `skb_try_coalesce`, records the result, and decodes the first three
post-call fragment descriptors from the destination skb. This makes it
possible to compare a reassembly head's newly planted `netmem` pointers with
the current task-fragment page rather than inferring the relationship from
source alone.
