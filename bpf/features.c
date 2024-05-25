// SPDX-License-Identifier: GPL-2.0
/* Copyright 2024 Leon Hwang. */

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} __events SEC(".maps");

SEC("tc")
int vista_dummy_tc(struct __sk_buff *skb) {
	return 0;
}

SEC("fentry/vista_dummy_tc")
int BPF_PROG(detect_bpf_skb_out, struct sk_buff *skb) {
	u64 zero = 0;
	u64 flags;

	flags = (((u64) sizeof(zero)) << 32) | BPF_F_CURRENT_CPU;
	bpf_skb_output(skb, &__events, flags, &zero, sizeof(zero));

	return BPF_OK;
}

SEC("xdp")
int vista_dummy_xdp(struct xdp_buff *xdp) {
	return XDP_PASS;
}

SEC("fentry/vista_dummy_xdp")
int BPF_PROG(detect_bpf_xdp_out, struct xdp_buff *xdp) {
	u64 zero = 0;
	u64 flags;

	flags = (((u64) sizeof(zero)) << 32) | BPF_F_CURRENT_CPU;
	bpf_xdp_output(xdp, &__events, flags, &zero, sizeof(zero));

	return BPF_OK;
}

char _license[] SEC("license") = "GPL";