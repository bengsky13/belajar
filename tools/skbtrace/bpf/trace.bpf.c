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
#define BPF_FUNC_get_current_task 35
#define BPF_FUNC_probe_read_kernel 113
#define BPF_FUNC_ringbuf_reserve 131
#define BPF_FUNC_ringbuf_submit 132

static __u64 (*bpf_get_current_pid_tgid)(void) =
	(void *)BPF_FUNC_get_current_pid_tgid;
static void *(*bpf_get_current_task)(void) =
	(void *)BPF_FUNC_get_current_task;
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
	unsigned int tail;
	unsigned int end;
	__u16 csum_start;
	__u16 csum_offset;
	__u16 transport_header;
	__u16 network_header;
	unsigned char *head;
	unsigned char *data;
} __attribute__((preserve_access_index));

struct page;
struct page_frag {
	struct page *page;
	__u32 offset;
	__u32 size;
} __attribute__((preserve_access_index));

struct task_struct {
	struct page_frag task_frag;
} __attribute__((preserve_access_index));

struct bpf_raw_tracepoint_args {
	__u64 args[0];
};

struct event {
	__u32 kind;
	__u32 tgid;
	__u32 tid;
	__u32 pad;
	__u64 skb;
	__u64 head;
	__u64 data;
	__u32 len;
	__u32 data_len;
	__u32 head_len;
	__u32 data_offset;
	__u32 tail_offset;
	__u32 end_offset;
	__u64 task_frag_page;
	__u32 task_frag_offset;
	__u32 task_frag_size;
	__u16 network_header;
	__u16 transport_header;
	__u16 csum_start;
	__u16 csum_offset;
	__u8 packet[64];
	__u8 tail[128];
	__u8 shinfo[96];
	__u8 skb_object[96];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

enum event_kind {
	EVENT_NET_DEV_QUEUE = 1,
	EVENT_NET_DEV_START_XMIT = 2,
	EVENT_KFREE_SKB = 3,
	EVENT_NETIF_RECEIVE_SKB = 4,
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
	__u32 tail_offset;
	__u32 end_offset;
	__u64 pid_tgid;
	struct task_struct *task;
	struct page *task_frag_page;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	CORE_READ_INTO(&head, skb, head);
	CORE_READ_INTO(&data, skb, data);
	CORE_READ_INTO(&len, skb, len);
	CORE_READ_INTO(&data_len, skb, data_len);
	CORE_READ_INTO(&tail_offset, skb, tail);
	CORE_READ_INTO(&end_offset, skb, end);
	head_len = len - data_len;

	pid_tgid = bpf_get_current_pid_tgid();
	e->kind = kind;
	e->tgid = (__u32)(pid_tgid >> 32);
	e->tid = (__u32)pid_tgid;
	e->pad = 0;
	e->skb = (__u64)skb;
	e->head = (__u64)head;
	e->data = (__u64)data;
	e->len = len;
	e->data_len = data_len;
	e->head_len = head_len;
	e->data_offset = (__u32)(data - head);
	e->tail_offset = tail_offset;
	e->end_offset = end_offset;
	task = bpf_get_current_task();
	CORE_READ_INTO(&task_frag_page, task, task_frag.page);
	e->task_frag_page = (__u64)task_frag_page;
	CORE_READ_INTO(&e->task_frag_offset, task, task_frag.offset);
	CORE_READ_INTO(&e->task_frag_size, task, task_frag.size);
	CORE_READ_INTO(&e->network_header, skb, network_header);
	CORE_READ_INTO(&e->transport_header, skb, transport_header);
	CORE_READ_INTO(&e->csum_start, skb, csum_start);
	CORE_READ_INTO(&e->csum_offset, skb, csum_offset);
	bpf_probe_read_kernel(e->packet, sizeof(e->packet), data);
	bpf_probe_read_kernel(e->tail, sizeof(e->tail), data + head_len);
	bpf_probe_read_kernel(e->shinfo, sizeof(e->shinfo), head + end_offset);
	bpf_probe_read_kernel(e->skb_object, sizeof(e->skb_object), skb);
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

SEC("raw_tracepoint/kfree_skb")
int trace_kfree_skb(struct bpf_raw_tracepoint_args *ctx)
{
	return emit((struct sk_buff *)ctx->args[0], EVENT_KFREE_SKB);
}

SEC("raw_tracepoint/netif_receive_skb")
int trace_netif_receive_skb(struct bpf_raw_tracepoint_args *ctx)
{
	return emit((struct sk_buff *)ctx->args[0], EVENT_NETIF_RECEIVE_SKB);
}

char LICENSE[] SEC("license") = "GPL";
