// SPDX-License-Identifier: GPL-2.0
/* Copyright Leon Hwang */

#ifndef __TCPLIFE_H_
#define __TCPLIFE_H_

#include "vmlinux.h"

#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"

#define TASK_COMM_LEN   16

struct tcp_receive_reset_args {
	unsigned long long unused;

	void *skaddr;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
	__u64 sock_cookie;
};

struct tcp_send_reset_args {
	unsigned long long unused;

	void *skbaddr;
	void *skaddr;
	int state;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

struct inet_sock_set_state_args {
	unsigned long long unused;

	void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

struct tcp_sock_info {
	union {
		__addrpair skc_addrpair;
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		__portpair skc_portpair;
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};

	__u8 reset;
	__u8 pad[3];

	__u32 pid;
	__u8 comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct tcp_sock_info);
	__uint(max_entries, 4096);
} tcp_socks SEC(".maps");

static __always_inline void
set_tcp_sock_info(struct sock *sk, u32 pid, const bool no_lookup) {
	struct tcp_sock_info sock = {};
	u64 key = (u64) sk;

	if (no_lookup || !bpf_map_lookup_elem(&tcp_socks, &key)) {
		sock.skc_addrpair = BPF_CORE_READ(sk, __sk_common.skc_addrpair);
		sock.skc_portpair = BPF_CORE_READ(sk, __sk_common.skc_portpair);
		sock.pid = pid;

		if (pid)
			bpf_get_current_comm(&sock.comm, sizeof(sock.comm));

		bpf_map_update_elem(&tcp_socks, &key, &sock, BPF_NOEXIST);
	}
}

static __always_inline struct tcp_sock_info *
lookup_and_delete_tcp_sock_info(struct sock *sk) {
	struct tcp_sock_info *sock;
	u64 key = (u64) sk;

	sock = bpf_map_lookup_elem(&tcp_socks, &key);
	if (!sock)
		return NULL;

	bpf_map_delete_elem(&tcp_socks, &key);
	return sock;
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, 4096);
} tcp_births SEC(".maps");

static __always_inline void
set_tcp_birth(struct sock *sk) {
	u64 ts = bpf_ktime_get_ns();
	u64 key = (u64) sk;

	if (!bpf_map_lookup_elem(&tcp_births, &key))
		bpf_map_update_elem(&tcp_births, &key, &ts, BPF_NOEXIST);
}

static __always_inline u64
lookup_and_delete_tcp_birth(struct sock *sk) {
	u64 key = (u64) sk;
	u64 *ts;

	ts = bpf_map_lookup_elem(&tcp_births, &key);
	if (!ts)
		return 0;

	bpf_map_delete_elem(&tcp_births, &key);
	return *ts;
}

#endif // __TCPLIFE_H_