// SPDX-License-Identifier: GPL-2.0
/* Copyright Leon Hwang */

#ifndef __IPTABLES_H_
#define __IPTABLES_H_

#include "vmlinux.h"

#include "bpf/bpf_helpers.h"

#ifdef __TARGET_ARCH_x86
struct xt_table_info {
	unsigned int size;
	unsigned int number;
	unsigned int initial_entries;
	unsigned int hook_entry[5];
	unsigned int underflow[5];
	unsigned int stacksize;
	void ***jumpstack;
	unsigned char entries[0];
};

struct xt_table {
	struct list_head list;
	unsigned int valid_hooks;
	struct xt_table_info *private;
	struct module *me;
	u_int8_t af;
	int priority;
	int (*table_init)(struct net *);
	const char name[32];
};
#endif

struct ipt_do_table_args {
	struct sk_buff *skb;
	struct nf_hook_state *state;
	struct xt_table *table;
	u64 start_ns;
} __packed;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct ipt_do_table_args);
	__uint(max_entries, 1024);
} ipt_do_table_args_map SEC(".maps");

#endif // __IPTABLES_H_