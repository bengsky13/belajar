// SPDX-License-Identifier: GPL-2.0
// Minimal CO-RE tracer for the local, disposable PwnEscape lab kernel.

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_FUNC_get_current_pid_tgid 14
#define BPF_FUNC_probe_read_kernel 113
#define BPF_FUNC_ringbuf_reserve 131
#define BPF_FUNC_ringbuf_submit 132

static __u64 (*bpf_get_current_pid_tgid)(void) =
	(void *)BPF_FUNC_get_current_pid_tgid;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size,
				      const void *unsafe_ptr) =
	(void *)BPF_FUNC_probe_read_kernel;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) =
	(void *)BPF_FUNC_ringbuf_reserve;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) =
	(void *)BPF_FUNC_ringbuf_submit;

struct sk_buff {
	unsigned int len;
	unsigned int data_len;
	__u16 csum_start;
	__u16 csum_offset;
	__u16 transport_header;
	__u16 network_header;
	unsigned char *head;
	unsigned char *data;
} __attribute__((preserve_access_index));

struct bpf_raw_tracepoint_args {
	__u64 args[0];
};

struct event {
	__u32 kind;
	__u32 pid;
	__u64 skb;
	__u64 head;
	__u64 data;
	__u32 len;
	__u32 data_len;
	__u32 head_len;
	__u32 data_offset;
	__u16 network_header;
	__u16 transport_header;
	__u16 csum_start;
	__u16 csum_offset;
	__u8 packet[64];
	__u8 tail[128];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

enum event_kind {
	EVENT_NET_DEV_QUEUE = 1,
	EVENT_NET_DEV_START_XMIT = 2,
};

#define CORE_READ_INTO(dst, obj, field)                                      \
	bpf_probe_read_kernel((dst), sizeof(*(dst)),                           \
			      __builtin_preserve_access_index(&(obj)->field))

static __attribute__((always_inline)) int emit(struct sk_buff *skb, __u32 kind)
{
	struct event *e;
	unsigned char *head;
	unsigned char *data;
	__u32 len;
	__u32 data_len;
	__u32 head_len;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	CORE_READ_INTO(&head, skb, head);
	CORE_READ_INTO(&data, skb, data);
	CORE_READ_INTO(&len, skb, len);
	CORE_READ_INTO(&data_len, skb, data_len);
	head_len = len - data_len;

	e->kind = kind;
	e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	e->skb = (__u64)skb;
	e->head = (__u64)head;
	e->data = (__u64)data;
	e->len = len;
	e->data_len = data_len;
	e->head_len = head_len;
	e->data_offset = (__u32)(data - head);
	CORE_READ_INTO(&e->network_header, skb, network_header);
	CORE_READ_INTO(&e->transport_header, skb, transport_header);
	CORE_READ_INTO(&e->csum_start, skb, csum_start);
	CORE_READ_INTO(&e->csum_offset, skb, csum_offset);
	bpf_probe_read_kernel(e->packet, sizeof(e->packet), data);
	bpf_probe_read_kernel(e->tail, sizeof(e->tail), data + head_len);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("raw_tracepoint/net_dev_queue")
int trace_net_dev_queue(struct bpf_raw_tracepoint_args *ctx)
{
	return emit((struct sk_buff *)ctx->args[0], EVENT_NET_DEV_QUEUE);
}

SEC("raw_tracepoint/net_dev_start_xmit")
int trace_net_dev_start_xmit(struct bpf_raw_tracepoint_args *ctx)
{
	return emit((struct sk_buff *)ctx->args[0], EVENT_NET_DEV_START_XMIT);
}

char LICENSE[] SEC("license") = "GPL";
