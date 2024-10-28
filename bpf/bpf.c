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

struct sk_key {
	__u32 local_ip4;
	__u32 remote_ip4;
	__u32 local_port;
	__u32 remote_port;
};

// client <--[key={0}]--> proxy <--[key={1}]--> server

// dispatch_sk maps a src 4-tuple key to a dst 4-tuple key
// e.g. [client <--> proxy socket] => [proxy <--> server socket],
// [proxy <--> server socket] => [client <--> proxy socket]
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SOCKOPS_MAP_SIZE);
	__type(key, struct sk_key);
	__type(value, struct sk_key);
} dispatch_sk SEC(".maps");

// sockhash maps a 4-tuple key to a socket FD
struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, SOCKOPS_MAP_SIZE);
	__type(key, struct sk_key);
	__type(value, __u32); // socket FD
} sockhash SEC(".maps");


static inline void init_sk_key_from_skops(struct bpf_sock_ops *skops, struct sk_key *sk_key) {
	sk_key->local_ip4   = bpf_ntohl(skops->local_ip4);
	sk_key->remote_ip4  = bpf_ntohl(skops->remote_ip4);
	sk_key->local_port  = skops->local_port;
	sk_key->remote_port = bpf_ntohl(skops->remote_port);
}

static inline void init_sk_key_from_sk_buff(struct __sk_buff *skb, struct sk_key *sk_key) {
	sk_key->local_ip4   = bpf_ntohl(skb->local_ip4);
	sk_key->remote_ip4  = bpf_ntohl(skb->remote_ip4);
	sk_key->local_port  = skb->local_port;
	sk_key->remote_port = bpf_ntohl(skb->remote_port);
}

SEC("sockops/prog")
int sockops_prog(struct bpf_sock_ops *skops) {
	// Only process IPv4 sockets
	if (skops == NULL || skops->family != AF_INET)
		return 0;

	// Initialize the 4-tuple key
	struct sk_key sk_key = {};
	init_sk_key_from_skops(skops, &sk_key);

	switch (skops->op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: // SYN-ACK
		bpf_sock_hash_update(skops, &sockhash, &sk_key, BPF_ANY);
		break;
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: // SYN
		bpf_sock_hash_update(skops, &sockhash, &sk_key, BPF_ANY);
		break;
	case BPF_SOCK_OPS_STATE_CB:
		// Socket changed state. args[0] stores the previous state.
		// Perform cleanup of map entries if socket is exiting
		// the 'established' state,
		if (skops->args[0] == BPF_TCP_ESTABLISHED) {
			bpf_map_delete_elem(&sockhash, &sk_key);
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

	// Initialize the 4-tuple key
	struct sk_key sk_key = {};
	init_sk_key_from_sk_buff(skb, &sk_key);

	// lookup in dispatch_sk for the dst 4-tuple key to dispatch to
	struct sk_key *dispatch_sk_key = bpf_map_lookup_elem(&dispatch_sk, &sk_key);
	if (dispatch_sk_key == NULL) {
		bpf_printk("Did not find socket with key =>\n");
		bpf_printk("\tlocal_ip4: %d\n", sk_key.local_ip4);
		bpf_printk("\tremote_ip4: %d\n", sk_key.remote_ip4);
		bpf_printk("\tlocal_port: %d\n", sk_key.local_port);
		bpf_printk("\tremote_port: %d\n", sk_key.remote_port);
		return SK_DROP;
	}

	// doesn't work return bpf_sk_redirect_map(skb, &sockhash, dispatch_sk_key, BPF_F_INGRESS);

	// works
	return bpf_sk_redirect_hash(skb, &sockhash, dispatch_sk_key, 0);
}

char _license[] SEC("license") = "GPL";
