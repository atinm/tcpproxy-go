//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SERVER_PORT 5000
#define PROXY_PORT 8000
// #define INJECT_MSG

#define AF_INET 2
#define SOCKOPS_MAP_SIZE 65535

#undef bpf_printk
#define bpf_printk(fmt, ...)                            \
({                                                      \
        static const char ____fmt[] = fmt;              \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

enum {
	SOCK_TYPE_ACTIVE  = 0,
	SOCK_TYPE_PASSIVE = 1,
};

// client <--[key={0}]--> proxy <--[key={1}]--> server

// dispatch_sk maps a local ip:local port socket dst local ip:local port socket key
// local ip:local port is saved in a __u64
// e.g. [client <--> proxy socket] => [proxy <--> server socket],
// [proxy <--> server socket] => [client <--> proxy socket]
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SOCKOPS_MAP_SIZE);
	__type(key, __u32); // local port in host order
	__type(value, __u32); // local port to dispatch to in host order
} dispatch_sk SEC(".maps");

// sockmap maps a local port to a socket FD
struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, SOCKOPS_MAP_SIZE);
	__type(key, __u32); // local port in host order
	__type(value, __u32); // socket FD
} sockmap SEC(".maps");

SEC("sockops/prog")
int sockops_prog(struct bpf_sock_ops *skops) {
	// Only process IPv4 sockets
	if (skops == NULL || skops->family != AF_INET)
		return 0;

	__u32 key = skops->local_port;

	switch (skops->op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: // SYN-ACK
		bpf_sock_map_update(skops, &sockmap, &key, BPF_ANY);
		break;
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: // SYN
		bpf_sock_map_update(skops, &sockmap, &key, BPF_ANY);
		break;
	case BPF_SOCK_OPS_STATE_CB:
		// Socket changed state. args[0] stores the previous state.
		// Perform cleanup of map entries if socket is exiting
		// the 'established' state,
		if (skops->args[0] == BPF_TCP_ESTABLISHED) {
			bpf_map_delete_elem(&sockmap, &key);
		}
		break;
	}

	return SK_PASS;
}

SEC("sk_skb/stream_verdict/prog")
int sk_skb_stream_verdict_prog(struct __sk_buff *skb) {
#if 0
	// inject a 5 bytes message "PASS\n" for each packet at the beginning
	bpf_skb_adjust_room(skb, 5, 0, 0);
	__u8 *data = (void *)(long)skb->data;
	__u8 *data_end = (void *)(long)skb->data_end;
	if (data + 5 <= data_end) {
		__builtin_memcpy(data, "PASS\n", 5);
	}
#endif

	if (skb->protocol != AF_INET)
		return SK_PASS;

	__u32 key = skb->local_port;

	// lookup in dispatch_sk for the dst 4-tuple key to dispatch to
	__u32 *dispatch_sk_key = bpf_map_lookup_elem(&dispatch_sk, &key);
	if (dispatch_sk_key == NULL) {
		bpf_printk("Did not find socket with key =>\n");
		bpf_printk("\tlocal_port: %d\n", key);
		return SK_DROP;
	}

	// doesn't work return bpf_sk_redirect_map(skb, &sockmap, dispatch_sk_key, BPF_F_INGRESS);

	// works
	return bpf_sk_redirect_map(skb, &sockmap, *dispatch_sk_key, 0);
}

char _license[] SEC("license") = "GPL";
