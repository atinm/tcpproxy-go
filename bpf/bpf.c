//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SERVER_PORT 5000
#define PROXY_PORT 8000
// #define INJECT_MSG

// client <--[key=0]--> proxy <--[key=1]--> server

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 32);
	__type(key, __u32);
	__type(value, __u32); // socket FD
} sockmap SEC(".maps");

SEC("sockops/prog")
int sockops_prog(struct bpf_sock_ops *skops) {
	switch (skops->op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: // SYN-ACK
		if (skops->local_port == PROXY_PORT) {
			__u32 key = 0;
			bpf_sock_map_update(skops, &sockmap, &key, BPF_ANY);
		}
		break;
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: // SYN
		if (bpf_ntohl(skops->remote_port) == SERVER_PORT) {
			__u32 key = 1;
			bpf_sock_map_update(skops, &sockmap, &key, BPF_ANY);
		}
		break;
	case BPF_SOCK_OPS_STATE_CB:
		// Socket changed state. args[0] stores the previous state.
		// Perform cleanup of map entries if socket is exiting
		// the 'established' state,
		if (skops->args[0] == BPF_TCP_ESTABLISHED) {
			if (bpf_ntohl(skops->remote_port) == SERVER_PORT) {
				__u32 key = 1;
				bpf_map_delete_elem(&sockmap, &key);
			} else if (skops->local_port == PROXY_PORT) {
				__u32 key = 0;
				bpf_map_delete_elem(&sockmap, &key);
			}
		}
		break;
	}

	return 0;
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

	if (skb->local_port == PROXY_PORT) {
		// doesn't work
		// return bpf_sk_redirect_map(skb, &sockmap, 0, BPF_F_INGRESS);

		// works
		return bpf_sk_redirect_map(skb, &sockmap, 1, 0);
	}

	if (bpf_ntohl(skb->remote_port) == SERVER_PORT) {
		// doesn't work
		// return bpf_sk_redirect_map(skb, &sockmap, 1, BPF_F_INGRESS);

		// works
		return bpf_sk_redirect_map(skb, &sockmap, 0, 0);
	}

	return SK_DROP;
}

char _license[] SEC("license") = "GPL";
