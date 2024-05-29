// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_endian.h"
#include "bpf/bpf_ipv6.h"

#include "iptables.h"
#include "tcplife.h"

#define PRINT_SKB_STR_SIZE    2048

#define XT_TABLE_MAXNAMELEN   32
#define TCP_CA_NAME_MAX       16

#define AF_INET               2
#define AF_INET6              10

#define ETH_P_IP              0x800
#define ETH_P_IPV6            0x86dd
#define ETH_P_8021Q           0x8100

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define min(x, y) ({					\
	typeof(x) _min1 = (x);				\
	typeof(y) _min2 = (y);				\
	_min1 < _min2 ? _min1 : _min2;		\
})

const static bool TRUE = true;

volatile const static __u64 BPF_PROG_ADDR = 0;

union addr {
	u32 v4addr;
	struct {
		u64 d1;
		u64 d2;
	} v6addr;
} __packed;

struct skb_meta {
	u32 netns;
	u32 mark;
	u32 ifindex;
	u32 len;
	u32 mtu;
	u16 protocol;
	u8 pkt_type;
	u8 kfree_skb_reason;
	u32 kfree_skb_reason_enum;
} __packed;

struct tuple {
	union addr saddr;
	union addr daddr;
	u16 l3_proto;
	u8 l4_proto;
	u8 icmptype;
	union {
		struct {
			u16 sport;
			u16 dport;
		};
		struct {
			u16 icmpid;
			u16 icmpseq;
		};
	};
} __packed;

struct iptables_meta {
	char tablename[XT_TABLE_MAXNAMELEN];
	u64 delay;
	u32 verdict;
	u8 hook;
	u8 pf;
	u8 pad[2];
} __packed;

struct tcp_meta {
	u64 rx_bytes;
	u64 tx_bytes;

	u64 life_ns;
	u32 srtt_us;
	u32 retrans;
	u32 sk_mark;

	u8 reset;
	u8 pad[3];

	u8 cong[TCP_CA_NAME_MAX];
	u8 comm[TASK_COMM_LEN];
} __packed;

struct sk_meta {
	u32 skc_bound_ifindex;
	u32 sk_backlog_len;
	u32 sk_rcv_buff;
	u32 sk_snd_buff;
	u32 sk_priority;
	u32 sk_mark;
	u16 sk_type;
	u16 socket_state;
	u8 skc_state;
	u8 skc_reuse_port;
	u8 with_socket;
	u8 socket_pad;
	u64 socket_file_inode;
	u64 socket_flags;
} __packed;

struct pcap_meta {
	u32 rx_queue;
	u32 cap_len;
	u8 action;
	u8 is_fexit;
	u16 pad;
} __packed;

u64 print_skb_id = 0;

enum event_type {
	EVENT_TYPE_KPROBE = 0,
	EVENT_TYPE_TC = 1,
	EVENT_TYPE_XDP = 2,
};

enum event_source {
	EVENT_SOURCE_SKB = 0,
	EVENT_SOURCE_SK = 1,
	EVENT_SOURCE_IPTABLES = 2,
	EVENT_SOURCE_TCP = 3,
	EVENT_SOURCE_PCAP = 4,
};

struct event_t {
	u32 pid;
	u8 type;
	u8 source;
	u16 pad;
	u64 addr;
	u64 skb_addr;
	u64 ts;
	typeof(print_skb_id) print_skb_id;
	s64 print_stack_id;
	struct tuple tuple;
	struct skb_meta meta;
	u32 cpu_id;
	union {
		struct sk_meta sk;
		struct tcp_meta tcp;
		struct pcap_meta pcap;
		struct iptables_meta iptables;
	};
} __packed;

#define __sizeof_pcap_event \
	(sizeof(struct event_t) - sizeof(struct tcp_meta) + sizeof(struct pcap_meta))

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct event_t);
	__uint(max_entries, 1);
} event_buf SEC(".maps");

static __always_inline struct event_t *
get_event(void) {
	struct event_t *event;
	u32 key = 0;

	event = bpf_map_lookup_elem(&event_buf, &key);
	if (event)
		__builtin_memset(event, 0, sizeof(*event));

	return event;
}

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

#define MAX_TRACK_SIZE 1024
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, bool);
	__uint(max_entries, MAX_TRACK_SIZE);
} skb_addresses SEC(".maps");

struct config {
	u32 netns;
	u32 skb_mark;
	u32 sk_mark;
	u32 ifindex;
	u64 tcp_lifetime;
	__be32 addr;
	__be16 port_be;
	u16 port;
	u16 l4_proto;
	u16 is_set:1;
	u16 track_skb:1;
	u16 output_meta:1;
	u16 output_tuple:1;
	u16 output_skb:1;
	u16 output_stack:1;
	u16 output_iptables:1;
	u16 output_tcp:1;
	u16 output_sk:1;
	u16 output_pcap:1;
	u16 snap_len;
	u16 pad;
} __packed;

static volatile const struct config CFG;
#define cfg (&CFG)

#define MAX_STACK_DEPTH 50
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 256);
	__uint(key_size, sizeof(u32));
	__uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} print_stack_map SEC(".maps");

#ifdef OUTPUT_SKB
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 256);
	__type(key, u32);
	__type(value, char[PRINT_SKB_STR_SIZE]);
} print_skb_map SEC(".maps");
#endif

static __always_inline u32
get_netns(struct sk_buff *skb) {
	u32 netns = BPF_CORE_READ(skb, dev, nd_net.net, ns.inum);

	// if skb->dev is not initialized, try to get ns from sk->__sk_common.skc_net.net->ns.inum
	if (netns == 0)	{
		struct sock *sk = BPF_CORE_READ(skb, sk);
		if (sk != NULL)	{
			netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
		}
	}

	return netns;
}

static __always_inline bool
filter_meta(struct sk_buff *skb) {
	if (cfg->netns && get_netns(skb) != cfg->netns)
			return false;

	if (cfg->skb_mark && BPF_CORE_READ(skb, mark) != cfg->skb_mark)
		return false;

	if (cfg->ifindex != 0 && BPF_CORE_READ(skb, dev, ifindex) != cfg->ifindex)
		return false;

	return true;
}

static __noinline bool
filter_pcap_ebpf_l3(void *_skb, void *__skb, void *___skb, void *data, void* data_end)
{
	return data != data_end && _skb == __skb && __skb == ___skb;
}

static __always_inline bool
filter_pcap_l3(struct sk_buff *skb)
{
	void *skb_head = BPF_CORE_READ(skb, head);
	void *data = skb_head + BPF_CORE_READ(skb, network_header);
	void *data_end = skb_head + BPF_CORE_READ(skb, tail);
	return filter_pcap_ebpf_l3((void *)skb, (void *)skb, (void *)skb, data, data_end);
}

static __noinline bool
filter_pcap_ebpf_l2(void *_skb, void *__skb, void *___skb, void *data, void* data_end)
{
	return data != data_end && _skb == __skb && __skb == ___skb;
}

static __always_inline bool
filter_pcap_l2(struct sk_buff *skb)
{
	void *skb_head = BPF_CORE_READ(skb, head);
	void *data = skb_head + BPF_CORE_READ(skb, mac_header);
	void *data_end = skb_head + BPF_CORE_READ(skb, tail);
	return filter_pcap_ebpf_l2((void *)skb, (void *)skb, (void *)skb, data, data_end);
}

static __always_inline bool
filter_pcap(struct sk_buff *skb) {
	if (BPF_CORE_READ(skb, mac_len) == 0)
		return filter_pcap_l3(skb);
	return filter_pcap_l2(skb);
}

static __always_inline bool
filter(struct sk_buff *skb) {
	return filter_pcap(skb) && filter_meta(skb);
}

static __always_inline void
set_meta(struct sk_buff *skb, struct skb_meta *meta) {
	meta->netns = get_netns(skb);
	meta->mark = BPF_CORE_READ(skb, mark);
	meta->len = BPF_CORE_READ(skb, len);
	meta->protocol = BPF_CORE_READ(skb, protocol);
	meta->ifindex = BPF_CORE_READ(skb, dev, ifindex);
	meta->mtu = BPF_CORE_READ(skb, dev, mtu);
	meta->pkt_type = BPF_CORE_READ_BITFIELD_PROBED(skb, pkt_type);
}

static __always_inline void
__set_tuple(struct tuple *tpl, void *data, u16 l3_off, bool is_ipv4) {
	u16 l4_off;

	if (is_ipv4) {
		struct iphdr *ip4 = (struct iphdr *) (data + l3_off);
		BPF_CORE_READ_INTO(&tpl->saddr, ip4, saddr);
		BPF_CORE_READ_INTO(&tpl->daddr, ip4, daddr);
		tpl->l4_proto = BPF_CORE_READ(ip4, protocol);
		tpl->l3_proto = ETH_P_IP;
		l4_off = l3_off + BPF_CORE_READ_BITFIELD_PROBED(ip4, ihl) * 4;

	} else {
		struct ipv6hdr *ip6 = (struct ipv6hdr *) (data + l3_off);
		BPF_CORE_READ_INTO(&tpl->saddr, ip6, saddr);
		BPF_CORE_READ_INTO(&tpl->daddr, ip6, daddr);
		tpl->l4_proto = BPF_CORE_READ(ip6, nexthdr); // TODO: ipv6 l4 protocol
		tpl->l3_proto = ETH_P_IPV6;
		l4_off = l3_off + ipv6_hdrlen(ip6);
	}

	if (tpl->l4_proto == IPPROTO_TCP) {
		struct tcphdr *tcp = (struct tcphdr *) (data + l4_off);
		tpl->sport= BPF_CORE_READ(tcp, source);
		tpl->dport= BPF_CORE_READ(tcp, dest);
	} else if (tpl->l4_proto == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *) (data + l4_off);
		tpl->sport= BPF_CORE_READ(udp, source);
		tpl->dport= BPF_CORE_READ(udp, dest);
	} else if (tpl->l4_proto == IPPROTO_ICMP) {
		struct icmphdr *icmp = (struct icmphdr *) (data + l4_off);
		tpl->icmpid = BPF_CORE_READ(icmp, un.echo.id);
		tpl->icmpseq = BPF_CORE_READ(icmp, un.echo.sequence);
		tpl->icmptype = BPF_CORE_READ(icmp, type);
	}
}

static __always_inline void
set_tuple(struct sk_buff *skb, struct tuple *tpl) {
	void *skb_head = BPF_CORE_READ(skb, head);
	u16 l3_off = BPF_CORE_READ(skb, network_header);

	struct iphdr *l3_hdr = (struct iphdr *) (skb_head + l3_off);
	u8 ip_vsn = BPF_CORE_READ_BITFIELD_PROBED(l3_hdr, version);

	if (ip_vsn !=4 && ip_vsn != 6)
		return;

	bool is_ipv4 = ip_vsn == 4;
	__set_tuple(tpl, skb_head, l3_off, is_ipv4);
}

#ifdef OUTPUT_SKB
static __always_inline void
set_skb_btf(struct sk_buff *skb, typeof(print_skb_id) *event_id) {
	static struct btf_ptr p = {};
	typeof(print_skb_id) id;
	char *str;

	p.type_id = bpf_core_type_id_kernel(struct sk_buff);
	p.ptr = skb;
	id = __sync_fetch_and_add(&print_skb_id, 1) % 256;

	str = bpf_map_lookup_elem(&print_skb_map, (u32 *) &id);
	if (!str) {
		return;
	}

	if (bpf_snprintf_btf(str, PRINT_SKB_STR_SIZE, &p, sizeof(p), 0) < 0) {
		return;
	}

	*event_id = id;
}
#endif

static __always_inline void
set_output(void *ctx, struct sk_buff *skb, struct event_t *event, const bool dropstack) {
	if (cfg->output_meta)
		set_meta(skb, &event->meta);

	if (cfg->output_tuple)
		set_tuple(skb, &event->tuple);

#ifdef OUTPUT_SKB
	if (cfg->output_skb)
		set_skb_btf(skb, &event->print_skb_id);
#endif

	if (cfg->output_stack || dropstack)
		event->print_stack_id = bpf_get_stackid(ctx, &print_stack_map, BPF_F_FAST_STACK_CMP);
}

static __always_inline bool
filter_skb(struct sk_buff *skb) {
	u64 skb_addr = (u64) BPF_CORE_READ(skb, head);
	struct sock *sk = BPF_CORE_READ(skb, sk);
	u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

	if (sk && family != AF_INET && family != AF_INET6)
		return false;

	if (!cfg->track_skb)
		return filter(skb);

	if (!bpf_map_lookup_elem(&skb_addresses, &skb_addr)) {
		if (!filter(skb))
			return false;

		bpf_map_update_elem(&skb_addresses, &skb_addr, &TRUE, BPF_ANY);
	}

	return true;
}

static __always_inline void
set_event(void *ctx, struct sk_buff *skb, struct event_t *event, const bool dropstack) {
	set_output(ctx, skb, event, dropstack);

	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->ts = bpf_ktime_get_ns();
	event->cpu_id = bpf_get_smp_processor_id();
}

static __noinline bool
handle_everything(struct sk_buff *skb, void *ctx, struct event_t *event, const bool dropstack) {
	if (cfg->is_set && !filter_skb(skb))
		return false;

	set_event(ctx, skb, event, dropstack);

	return true;
}

static __always_inline int
kprobe_skb(struct sk_buff *skb, struct pt_regs *ctx, bool has_get_func_ip,
		   bool has_kfree_skb_reason, const bool dropstack) {
	struct event_t *event = get_event();
	if (!event)
		return BPF_OK;

	if (!handle_everything(skb, ctx, event, dropstack))
		return BPF_OK;

	if (has_kfree_skb_reason) {
		event->meta.kfree_skb_reason = 1;
		event->meta.kfree_skb_reason_enum = (u32)(u64) PT_REGS_PARM2(ctx);
	}

	event->skb_addr = (u64) BPF_CORE_READ(skb, head);
	event->addr = has_get_func_ip ? bpf_get_func_ip(ctx) : PT_REGS_IP(ctx);
	event->type = EVENT_TYPE_KPROBE;
	event->source = EVENT_SOURCE_SKB;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

	return BPF_OK;
}

#ifdef HAS_KPROBE_MULTI
#define SKK_KPROBE_TYPE "kprobe.multi"
#define SKK_HAS_GET_FUNC_IP true
#else
#define SKK_KPROBE_TYPE "kprobe"
#define SKK_HAS_GET_FUNC_IP false
#endif /* HAS_KPROBE_MULTI */

#define SKK_ADD_KPROBE(X)                                                     \
  SEC(SKK_KPROBE_TYPE "/skb-" #X)                                             \
  int kprobe_skb_##X(struct pt_regs *ctx) {                                   \
    struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM##X(ctx);            \
    return kprobe_skb(skb, ctx, SKK_HAS_GET_FUNC_IP, false, false);           \
  }

SKK_ADD_KPROBE(1)
SKK_ADD_KPROBE(2)
SKK_ADD_KPROBE(3)
SKK_ADD_KPROBE(4)
SKK_ADD_KPROBE(5)

SEC("kprobe/kfree_skb_reason")
int kprobe_kfree_skb_reason(struct pt_regs *ctx) {
	struct sk_buff *skb = (void *) PT_REGS_PARM1(ctx);
	return kprobe_skb(skb, ctx, SKK_HAS_GET_FUNC_IP, true, false);
}

SEC("kprobe/__kfree_skb")
int kprobe_kfree_skb(struct pt_regs *ctx) {
	struct sk_buff *skb = (void *) PT_REGS_PARM1(ctx);
	return kprobe_skb(skb, ctx, SKK_HAS_GET_FUNC_IP, false, true);
}

#undef SKK_KPROBE
#undef SKK_HAS_GET_FUNC_IP
#undef SKK_KPROBE_TYPE

SEC("kprobe/skb_lifetime_termination")
int kprobe_skb_lifetime_termination(struct pt_regs *ctx) {
	struct sk_buff *skb = (void *) PT_REGS_PARM1(ctx);
	u64 skb_addr = (u64) BPF_CORE_READ(skb, head);

	bpf_map_delete_elem(&skb_addresses, &skb_addr);

	return BPF_OK;
}

static __always_inline int
track_skb_clone(struct sk_buff *old, struct sk_buff *new) {
	u64 skb_addr_old = (u64) BPF_CORE_READ(old, head);
	u64 skb_addr_new = (u64) BPF_CORE_READ(new, head);
	if (bpf_map_lookup_elem(&skb_addresses, &skb_addr_old))
		bpf_map_update_elem(&skb_addresses, &skb_addr_new, &TRUE, BPF_ANY);

	return BPF_OK;
}

SEC("fexit/skb_clone")
int BPF_PROG(fexit_skb_clone, struct sk_buff *old, gfp_t mask, struct sk_buff *new) {
	if (new)
		return track_skb_clone(old, new);

	return BPF_OK;
}

SEC("fexit/skb_copy")
int BPF_PROG(fexit_skb_copy, struct sk_buff *old, gfp_t mask, struct sk_buff *new) {
	if (new)
		return track_skb_clone(old, new);

	return BPF_OK;
}

static __always_inline void
set_skb_pcap_meta(struct sk_buff *skb, struct pcap_meta *pcap, int action, bool is_fexit) {
	u32 len = BPF_CORE_READ(skb, len);
	pcap->rx_queue = BPF_CORE_READ(skb, queue_mapping);
	pcap->cap_len = min(len, cfg->snap_len);
	pcap->action = action;
	pcap->is_fexit = is_fexit;
}

static __always_inline void
output_skb_pcap_event(struct sk_buff *skb, struct event_t *event, int action, bool is_fexit) {
	event->source = EVENT_SOURCE_PCAP;
	set_skb_pcap_meta(skb, &event->pcap, action, is_fexit);

	u64 flags = (((u64) event->pcap.cap_len) << 32) | BPF_F_CURRENT_CPU;
	bpf_skb_output(skb, &events, flags, event, __sizeof_pcap_event);
}

static __noinline void
handle_tc_skb(struct sk_buff *skb, void *ctx, int action, bool is_fexit, const bool pcap) {
	struct event_t *event = get_event();
	if (!event)
		return;

	if (!handle_everything(skb, ctx, event, false))
		return;

	event->skb_addr = (u64) BPF_CORE_READ(skb, head);
	event->addr = BPF_PROG_ADDR;
	event->type = EVENT_TYPE_TC;
	event->source = EVENT_SOURCE_SKB;

	if (!cfg->output_pcap) {
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
		return;
	}

	if (pcap) {
		output_skb_pcap_event(skb, event, action, is_fexit);
	}
}

SEC("fentry/tc")
int BPF_PROG(fentry_tc, struct sk_buff *skb) {
	handle_tc_skb(skb, ctx, 0, false, false);

	return BPF_OK;
}

SEC("fentry/tc")
int BPF_PROG(fentry_tc_pcap, struct sk_buff *skb) {
	handle_tc_skb(skb, ctx, 0, false, true);

	return BPF_OK;
}

SEC("fexit/tc")
int BPF_PROG(fexit_tc, struct sk_buff *skb, int action) {
	handle_tc_skb(skb, ctx, action, true, false);

	return BPF_OK;
}

SEC("fexit/tc")
int BPF_PROG(fexit_tc_pcap, struct sk_buff *skb, int action) {
	handle_tc_skb(skb, ctx, action, true, true);

	return BPF_OK;
}

static __always_inline bool
filter_xdp_netns(struct xdp_buff *xdp) {
	if (cfg->netns && BPF_CORE_READ(xdp, rxq, dev, nd_net.net, ns.inum) != cfg->netns)
		return false;

	return true;
}

static __always_inline bool
filter_xdp_ifindex(struct xdp_buff *xdp) {
	if (cfg->ifindex && BPF_CORE_READ(xdp, rxq, dev, ifindex) != cfg->ifindex)
		return false;

	return true;
}

static __always_inline bool
filter_xdp_meta(struct xdp_buff *xdp) {
	return filter_xdp_netns(xdp) && filter_xdp_ifindex(xdp);
}

static __always_inline bool
filter_xdp_pcap(struct xdp_buff *xdp) {
	void *data = (void *)(long) BPF_CORE_READ(xdp, data);
	void *data_end = (void *)(long) BPF_CORE_READ(xdp, data_end);
	return filter_pcap_ebpf_l2((void *)xdp, (void *)xdp, (void *)xdp, data, data_end);
}

static __always_inline bool
filter_xdp(struct xdp_buff *xdp) {
	return filter_xdp_pcap(xdp) && filter_xdp_meta(xdp);
}

static __always_inline bool
__filter(struct xdp_buff *xdp) {
	u64 addr = (u64) BPF_CORE_READ(xdp, data_hard_start);
	if (cfg->track_skb && bpf_map_lookup_elem(&skb_addresses, &addr))
		return true;

	if (!filter_xdp(xdp))
		return false;

	if (cfg->track_skb)
		bpf_map_update_elem(&skb_addresses, &addr, &TRUE, BPF_ANY);

	return true;
}

static __always_inline void
set_xdp_meta(struct xdp_buff *xdp, struct skb_meta *meta) {
	struct net_device *dev = BPF_CORE_READ(xdp, rxq, dev);
	meta->netns = BPF_CORE_READ(dev, nd_net.net, ns.inum);
	meta->ifindex = BPF_CORE_READ(dev, ifindex);
	meta->mtu = BPF_CORE_READ(dev, mtu);
	meta->len = BPF_CORE_READ(xdp, data_end) - BPF_CORE_READ(xdp, data);
}

static __always_inline void
set_xdp_tuple(struct xdp_buff *xdp, struct tuple *tpl) {
	void *data = (void *)(long) BPF_CORE_READ(xdp, data);
	void *data_end = (void *)(long) BPF_CORE_READ(xdp, data_end);
	struct ethhdr *eth = (struct ethhdr *) data;
	u16 l3_off = sizeof(*eth);
	u16 l4_off;

	__be16 proto = BPF_CORE_READ(eth, h_proto);
	if (proto == bpf_htons(ETH_P_8021Q)) {
		struct vlan_hdr *vlan = (struct vlan_hdr *) (eth + 1);
		proto = BPF_CORE_READ(vlan, h_vlan_encapsulated_proto);
		l3_off += sizeof(*vlan);
	}
	if (proto != bpf_htons(ETH_P_IP) && proto != bpf_htons(ETH_P_IPV6))
		return;

	bool is_ipv4 = proto == bpf_htons(ETH_P_IP);
	__set_tuple(tpl, data, l3_off, is_ipv4);
}

static __always_inline void
set_xdp_output(void *ctx, struct xdp_buff *xdp, struct event_t *event) {
	if (cfg->output_meta)
		set_xdp_meta(xdp, &event->meta);

	if (cfg->output_tuple)
		set_xdp_tuple(xdp, &event->tuple);

	if (cfg->output_stack)
		event->print_stack_id = bpf_get_stackid(ctx, &print_stack_map, BPF_F_FAST_STACK_CMP);
}

static __always_inline void
set_xdp_pcap_meta(struct xdp_buff *xdp, struct pcap_meta *pcap, u32 len, int action, bool is_fexit) {
	pcap->rx_queue = BPF_CORE_READ(xdp, rxq, queue_index);
	pcap->cap_len = min(len, cfg->snap_len);
	pcap->action = action;
	pcap->is_fexit = is_fexit;
}

static __always_inline void
output_xdp_pcap_event(struct xdp_buff *xdp, struct event_t *event, u32 len, int action, bool is_fexit) {
	event->source = EVENT_SOURCE_PCAP;
	set_xdp_pcap_meta(xdp, &event->pcap, len, action, is_fexit);

	u64 flags = (((u64) event->pcap.cap_len) << 32) | BPF_F_CURRENT_CPU;
	bpf_xdp_output(xdp, &events, flags, event, __sizeof_pcap_event);
}

static __noinline void
handle_xdp_buff(struct xdp_buff *xdp, void *ctx, int verdict, bool is_fexit, const bool pcap) {
	struct event_t *event = get_event();
	if (!event)
		return;

	if (cfg->is_set) {
		if (!__filter(xdp))
			return;

		set_xdp_output(ctx, xdp, event);
	}

	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->ts = bpf_ktime_get_ns();
	event->cpu_id = bpf_get_smp_processor_id();
	event->skb_addr = (u64) BPF_CORE_READ(xdp, data_hard_start);
	event->addr = BPF_PROG_ADDR;
	event->type = EVENT_TYPE_XDP;
	event->source = EVENT_SOURCE_SKB;

	if (!cfg->output_pcap) {
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
		return;
	}

	if (pcap) {
		output_xdp_pcap_event(xdp, event, event->meta.len, verdict, is_fexit);
	}
}

SEC("fentry/xdp")
int BPF_PROG(fentry_xdp, struct xdp_buff *xdp) {
	handle_xdp_buff(xdp, ctx, 0, false, false);

	return BPF_OK;
}

SEC("fentry/xdp")
int BPF_PROG(fentry_xdp_pcap, struct xdp_buff *xdp) {
	handle_xdp_buff(xdp, ctx, 0, false, true);

	return BPF_OK;
}

SEC("fexit/xdp")
int BPF_PROG(fexit_xdp, struct xdp_buff *xdp, int verdict) {
	handle_xdp_buff(xdp, ctx, verdict, true, false);

	return BPF_OK;
}

SEC("fexit/xdp")
int BPF_PROG(fexit_xdp_pcap, struct xdp_buff *xdp, int verdict) {
	handle_xdp_buff(xdp, ctx, verdict, true, true);

	return BPF_OK;
}

static __always_inline void
set_iptables(struct xt_table *table, struct nf_hook_state *state, u32 verdict,
			 u64 delay, struct iptables_meta *iptables)
{
	if (table)
		bpf_probe_read_kernel_str(iptables->tablename, sizeof(iptables->tablename), table->name);
	BPF_CORE_READ_INTO(&iptables->hook, state, hook);
	BPF_CORE_READ_INTO(&iptables->pf, state, pf);
	iptables->verdict = verdict;
	iptables->delay = delay;
}

static __always_inline int
ipt_do_table_entry(struct pt_regs *ctx, struct sk_buff *skb,
				   struct nf_hook_state *state, struct xt_table *table) {
	if (cfg->is_set && !filter_skb(skb))
		return BPF_OK;

	struct ipt_do_table_args args = {
		.skb = skb,
		.state = state,
		.table = table,
		.start_ns = bpf_ktime_get_ns(),
	};

	u64 key = PT_REGS_SP(ctx);
	bpf_map_update_elem(&ipt_do_table_args_map, &key, &args, BPF_ANY);

	return BPF_OK;
}

static __always_inline int
ipt_do_table_exit(struct pt_regs *ctx, uint verdict) {
	u64 key = PT_REGS_SP(ctx) - 8;
	struct ipt_do_table_args *args = bpf_map_lookup_elem(&ipt_do_table_args_map, &key);
	if (!args)
		return BPF_OK;

	bpf_map_delete_elem(&ipt_do_table_args_map, &key);

	struct event_t *event = get_event();
	if (!event)
		return BPF_OK;

	if (cfg->is_set) {
		set_event(ctx, args->skb, event, false);

		if (cfg->output_iptables) {
			u64 delay = bpf_ktime_get_ns() - args->start_ns;
			set_iptables(args->table, args->state, verdict, delay, &event->iptables);
		}
	}

	struct sk_buff *skb = args->skb;
	event->skb_addr = (u64) BPF_CORE_READ(skb, head);
	event->addr = PT_REGS_IP(ctx);
	event->type = EVENT_TYPE_KPROBE;
	event->source = EVENT_SOURCE_IPTABLES;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

	return BPF_OK;
}

// >= 5.16

SEC("kprobe/ipt_do_table")
int BPF_KPROBE(kprobe_ipt_do_table, struct xt_table *table, struct sk_buff *skb,
			   struct nf_hook_state *state)
{
	return ipt_do_table_entry(ctx, skb, state, table);
};

// < 5.16

SEC("kprobe/ipt_do_table")
int BPF_KPROBE(kprobe_ipt_do_table_old, struct sk_buff *skb,
			   struct nf_hook_state *state, struct xt_table *table)
{
	return ipt_do_table_entry(ctx, skb, state, table);
}

SEC("kretprobe/ipt_do_table")
int BPF_KRETPROBE(kretprobe_ipt_do_table, uint ret)
{
	return ipt_do_table_exit(ctx, ret);
}

SEC("kprobe/nf_hook_slow")
int BPF_KPROBE(kprobe_nf_hook_slow, struct sk_buff *skb, struct nf_hook_state *state)
{
	return ipt_do_table_entry(ctx, skb, state, NULL);
}

SEC("kretprobe/nf_hook_slow")
int BPF_KRETPROBE(kretprobe_nf_hook_slow, uint ret)
{
	return ipt_do_table_exit(ctx, ret);
}

static __always_inline bool
filter_sk_meta(struct sock *sk) {
	if (cfg->netns && BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum) != cfg->netns)
		return false;

	__u32 sk_mark = BPF_CORE_READ(sk, sk_mark);
	if (cfg->sk_mark && sk_mark != cfg->sk_mark)
		return false;

	return true;
}

static __always_inline bool
filter_sk_tuple(struct sock *sk) {
	__u32 saddr, daddr;
	__u16 sport, dport;
	__u16 protocol;
	__u16 family;

	saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	protocol = BPF_CORE_READ(sk, sk_protocol);

	if (family != AF_INET && family != AF_INET6)
		return false;

	if (cfg->l4_proto && protocol != cfg->l4_proto)
		return false;

	if (cfg->addr && (saddr != cfg->addr && daddr != cfg->addr))
		return false;

	if (cfg->port && (sport != cfg->port && dport != cfg->port_be))
		return false;

	return true;
}

static __always_inline bool
filter_sk(struct sock *sk) {
	return filter_sk_meta(sk) && filter_sk_tuple(sk);
}

static __always_inline void
set_skb_meta(struct sock *sk, struct skb_meta *meta) {
	meta->netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
}

static __always_inline void
set_sk_meta(struct sock *sk, struct sk_meta *meta) {
	meta->skc_state = BPF_CORE_READ(sk, __sk_common.skc_state);
	meta->skc_reuse_port = BPF_CORE_READ_BITFIELD_PROBED(sk, __sk_common.skc_reuseport);
	meta->skc_bound_ifindex = BPF_CORE_READ(sk, __sk_common.skc_bound_dev_if);
	// meta->sk_rx_dst_ifindex = BPF_CORE_READ(sk, sk_rx_dst_ifindex);
	meta->sk_backlog_len = BPF_CORE_READ(sk, sk_backlog.len);
	meta->sk_rcv_buff = BPF_CORE_READ(sk, sk_rcvbuf);
	meta->sk_snd_buff = BPF_CORE_READ(sk, sk_sndbuf);
	meta->sk_priority = BPF_CORE_READ(sk, sk_priority);
	meta->sk_mark = BPF_CORE_READ(sk, sk_mark);
	meta->sk_type = BPF_CORE_READ(sk, sk_type);

	struct socket *sock = BPF_CORE_READ(sk, sk_socket);
	if (!sock)
		return;

	meta->with_socket = 1;
	meta->socket_state = BPF_CORE_READ(sock, state);
	meta->socket_flags = BPF_CORE_READ(sock, flags);
	meta->socket_file_inode = BPF_CORE_READ(sock, file, f_inode, i_ino);
}

static __always_inline void
set_sk_tuple(struct sock *sk, u8 l4proto, struct tuple *tpl) {
	tpl->l3_proto = ETH_P_IP;
	tpl->l4_proto = l4proto;
	tpl->saddr.v4addr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	tpl->daddr.v4addr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	tpl->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	tpl->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

	tpl->sport = bpf_htons(tpl->sport);
}

static __always_inline void
set_sk_output(void *ctx, struct sock *sk, u8 l4proto, struct event_t *event) {
	if (cfg->output_meta)
		set_skb_meta(sk, &event->meta);

	if (cfg->output_tuple)
		set_sk_tuple(sk, l4proto, &event->tuple);

	if (cfg->output_stack)
		event->print_stack_id = bpf_get_stackid(ctx, &print_stack_map, BPF_F_FAST_STACK_CMP);
}

static __always_inline int
kprobe_sk(struct sock *sk, struct pt_regs *ctx, const bool has_get_func_ip) {
	u16 protocol = BPF_CORE_READ(sk, sk_protocol);
	if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP && protocol != IPPROTO_ICMP)
		return BPF_OK;

	struct event_t *event = get_event();
	if (!event)
		return BPF_OK;

	if (cfg->is_set) {
		if (!filter_sk(sk))
			return BPF_OK;

		set_sk_output(ctx, sk, (u8) protocol, event);

		if (cfg->output_sk)
			set_sk_meta(sk, &event->sk);
	}

	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->ts = bpf_ktime_get_ns();
	event->cpu_id = bpf_get_smp_processor_id();

	event->skb_addr = (u64) sk;
	event->addr = has_get_func_ip ? bpf_get_func_ip(ctx) : PT_REGS_IP(ctx);
	event->type = EVENT_TYPE_KPROBE;
	event->source = EVENT_SOURCE_SK;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

	return BPF_OK;
}

#ifdef HAS_KPROBE_MULTI
#define SKK_SK_KPROBE_TYPE "kprobe.multi"
#define SKK_SK_GET_FUNC_IP true
#else
#define SKK_SK_KPROBE_TYPE "kprobe"
#define SKK_SK_GET_FUNC_IP false
#endif /* HAS_KPROBE_MULTI */

#define SKK_SK_KPROBE(X)                                    \
  SEC(SKK_SK_KPROBE_TYPE "/sk-" #X)                         \
  int kprobe_sk_##X(struct pt_regs *ctx) {                  \
    struct sock *sk = (struct sock *) PT_REGS_PARM##X(ctx); \
    return kprobe_sk(sk, ctx, SKK_SK_GET_FUNC_IP);          \
  }

SKK_SK_KPROBE(1)
SKK_SK_KPROBE(2)
SKK_SK_KPROBE(3)
SKK_SK_KPROBE(4)
SKK_SK_KPROBE(5)

#undef SKK_SK_KPROBE
#undef SKK_SK_KPROBE_TYPE

static __always_inline bool
set_tcp(struct sock *sk, struct event_t *event) {

	struct tcp_meta *tcp = &event->tcp;

	struct tcp_sock_info *sock;
	sock = lookup_and_delete_tcp_sock_info(sk);
	if (sock) {
		tcp->reset = sock->reset;

		if (sock->pid) {
			event->pid = sock->pid;
			bpf_probe_read_kernel_str(tcp->comm, sizeof(tcp->comm), sock->comm);
		}
	}

	if (cfg->output_tuple) {
		if (sock) {
			event->tuple.l3_proto = ETH_P_IP;
			event->tuple.l4_proto = IPPROTO_TCP;
			event->tuple.saddr.v4addr = sock->skc_rcv_saddr;
			event->tuple.daddr.v4addr = sock->skc_daddr;
			event->tuple.sport = bpf_htons(sock->skc_num);
			event->tuple.dport = sock->skc_dport;

		} else {
			set_sk_tuple(sk, IPPROTO_TCP, &event->tuple);
		}
	}

	struct tcp_sock *tp = (struct tcp_sock *) sk;
	tcp->rx_bytes = BPF_CORE_READ(tp, bytes_received);
	tcp->tx_bytes = BPF_CORE_READ(tp, bytes_acked);
	tcp->retrans = BPF_CORE_READ(tp, retrans_out);
	tcp->srtt_us = BPF_CORE_READ(tp, srtt_us) >> 3;
	tcp->sk_mark = BPF_CORE_READ(sk, sk_mark);

	struct inet_connection_sock *icsk = (struct inet_connection_sock *) sk;
	const struct tcp_congestion_ops *ca_ops = BPF_CORE_READ(icsk, icsk_ca_ops);
	if (ca_ops)
		bpf_probe_read_kernel_str(tcp->cong, sizeof(tcp->cong), ca_ops->name);

	return true;
}

static __always_inline void
output_tcp(void *ctx, struct sock *sk, struct event_t *event) {
	if (cfg->is_set) {
		if (cfg->output_meta)
			set_skb_meta(sk, &event->meta);

		if (cfg->output_stack)
			event->print_stack_id = bpf_get_stackid(ctx, &print_stack_map, BPF_F_FAST_STACK_CMP);

		if (cfg->output_tcp) {
			if (!set_tcp(sk, event))
				return;

		} else if (cfg->output_tuple) {
			set_sk_tuple(sk, IPPROTO_TCP, &event->tuple);
		}
	}

	event->addr = 0;
	event->skb_addr = (u64) sk;
	event->type = EVENT_TYPE_KPROBE;
	event->source = EVENT_SOURCE_TCP;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(kprobe_tcp_connect, struct sock *sk) {
	if (cfg->is_set && !filter_sk(sk))
		return BPF_OK;

	struct tcp_sock_info sock = {};
	sock.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&sock.comm, sizeof(sock.comm));

	u64 key = (u64) sk;
	bpf_map_update_elem(&tcp_socks, &key, &sock, BPF_ANY);

	return BPF_OK;
}

SEC("tp/tcp/tcp_send_reset")
int tp_tcp_send_reset(struct tcp_send_reset_args *args) {
	u16 family;
	bpf_probe_read_kernel(&family, sizeof(family), &args->family);
	if (family != AF_INET && family != AF_INET6)
		return BPF_OK;

	struct tcp_sock_info *sock;
	u64 key = (u64) args->skaddr;
	sock = bpf_map_lookup_elem(&tcp_socks, &key);
	if (sock)
		sock->reset = 1;

	return BPF_OK;
}

SEC("tracepoint/tcp/tcp_receive_reset")
int tp_tcp_recv_reset(struct tcp_receive_reset_args *args)
{
	u16 family;
	bpf_probe_read_kernel(&family, sizeof(family), &args->family);
	if (family != AF_INET && family != AF_INET6)
		return BPF_OK;

	struct tcp_sock_info *sock;
	u64 key = (u64) args->skaddr;
	sock = bpf_map_lookup_elem(&tcp_socks, &key);
	if (sock)
		sock->reset = 2;

	return BPF_OK;
}

SEC("tracepoint/sock/inet_sock_set_state")
int tp_inet_sock_set_state(struct inet_sock_set_state_args *args)
{
	u16 protocol, family;
	bpf_probe_read_kernel(&protocol, sizeof(protocol), &args->protocol);
	bpf_probe_read_kernel(&family, sizeof(family), &args->family);

	if (protocol != IPPROTO_TCP || (family != AF_INET && family != AF_INET6))
		return BPF_OK;

	struct sock *sk;
	bpf_probe_read_kernel(&sk, sizeof(sk), &args->skaddr);

	if (cfg->is_set && !filter_sk(sk))
		return BPF_OK;

	int newstate;
	bpf_probe_read_kernel(&newstate, sizeof(newstate), &args->newstate);

	if (newstate < TCP_FIN_WAIT1)
		set_tcp_birth(sk);

	u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (newstate == TCP_SYN_SENT || newstate == TCP_LAST_ACK)
		set_tcp_sock_info(sk, pid, false);

	if (newstate == TCP_ESTABLISHED || newstate == TCP_FIN_WAIT1 || newstate == TCP_FIN_WAIT2) {
		struct tcp_sock_info *sock;
		sock = bpf_map_lookup_elem(&tcp_socks, &sk);
		if (!sock) {
			set_tcp_sock_info(sk, pid, true);
		} else {
			if (!sock->pid)
				sock->pid = pid;
			if (!sock->pid)
				bpf_get_current_comm(&sock->comm, sizeof(sock->comm));
			if (!sock->skc_addrpair)
				sock->skc_addrpair = BPF_CORE_READ(sk, __sk_common.skc_addrpair);
			if (!sock->skc_portpair)
				sock->skc_portpair = BPF_CORE_READ(sk, __sk_common.skc_portpair);
		}
	}

	if (newstate != TCP_CLOSE)
		return BPF_OK;

	u64 ts = lookup_and_delete_tcp_birth(sk);
	if (!ts)
		return false;

	u64 life_ns = bpf_ktime_get_ns() - ts;
	if (cfg->tcp_lifetime && life_ns < cfg->tcp_lifetime)
		return BPF_OK;

	struct event_t *event = get_event();
	if (!event)
		return BPF_OK;

	event->pid = pid;
	bpf_get_current_comm(&event->tcp.comm, sizeof(event->tcp.comm));
	event->ts = bpf_ktime_get_ns();
	event->cpu_id = bpf_get_smp_processor_id();
	event->tcp.life_ns = life_ns;
	output_tcp(args, sk, event);

	return BPF_OK;
}

SEC("kprobe/tcp_v4_destroy_sock")
int BPF_KPROBE(kprobe_tcp_v4_destroy_sock, struct sock *sk) {
	lookup_and_delete_tcp_birth(sk);
	lookup_and_delete_tcp_sock_info(sk);

	return BPF_OK;
}

char __license[] SEC("license") = "Dual BSD/GPL";
