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
	__u8 tail[64];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

enum event_kind {
	EVENT_IP_FRAGMENT = 1,
	EVENT_CSUM_ENTER = 2,
	EVENT_CSUM_EXIT = 3,
};

#define CORE_READ(obj, field) __builtin_preserve_access_index((obj)->field)

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

	head = CORE_READ(skb, head);
	data = CORE_READ(skb, data);
	len = CORE_READ(skb, len);
	data_len = CORE_READ(skb, data_len);
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
	e->network_header = CORE_READ(skb, network_header);
	e->transport_header = CORE_READ(skb, transport_header);
	e->csum_start = CORE_READ(skb, csum_start);
	e->csum_offset = CORE_READ(skb, csum_offset);
	bpf_probe_read_kernel(e->packet, sizeof(e->packet), data);
	bpf_probe_read_kernel(e->tail, sizeof(e->tail), data + head_len);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/ip_do_fragment")
int trace_ip_do_fragment(__u64 *ctx)
{
	return emit((struct sk_buff *)ctx[2], EVENT_IP_FRAGMENT);
}

SEC("fentry/skb_checksum_help")
int trace_csum_enter(__u64 *ctx)
{
	return emit((struct sk_buff *)ctx[0], EVENT_CSUM_ENTER);
}

SEC("fexit/skb_checksum_help")
int trace_csum_exit(__u64 *ctx)
{
	return emit((struct sk_buff *)ctx[0], EVENT_CSUM_EXIT);
}

char LICENSE[] SEC("license") = "GPL";
