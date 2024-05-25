// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package vista

import "github.com/cilium/ebpf"

func TrimBpfSpec(spec *ebpf.CollectionSpec, f *Flags, haveFexit bool) {
	// fentry_tc&fentry_xdp are not used in the kprobe/kprobe-multi cases. So,
	// they should be deleted from the spec.
	tracingProgNames := []string{
		ProgNameFentryTC,
		ProgNameFexitTC,
		ProgNameFentryTCPcap,
		ProgNameFexitTCPcap,
		ProgNameFentryXDP,
		ProgNameFexitXDP,
		ProgNameFentryXDPPcap,
		ProgNameFexitXDPPcap,
	}
	for _, progName := range tracingProgNames {
		delete(spec.Programs, progName)
	}

	// If not tracking skb, deleting the skb-tracking programs to reduce loading
	// time.
	if !f.FilterTrackSkb {
		delete(spec.Programs, "kprobe_skb_lifetime_termination")
	}

	if !f.FilterTrackSkb || !haveFexit {
		delete(spec.Programs, "fexit_skb_clone")
		delete(spec.Programs, "fexit_skb_copy")
	}

	if !f.FilterTraceIptables {
		delete(spec.Programs, "kprobe_ipt_do_table")
		delete(spec.Programs, "kprobe_ipt_do_table_old")
		delete(spec.Programs, "kretprobe_ipt_do_table")
	}

	if !f.FilterTraceTCP {
		delete(spec.Programs, "kprobe_tcp_connect")
		delete(spec.Programs, "tp_tcp_send_reset")
		delete(spec.Programs, "tp_tcp_recv_reset")
		delete(spec.Programs, "tp_inet_sock_set_state")
		delete(spec.Programs, "kprobe_tcp_v4_destroy_sock")
	}

	if !f.FilterTraceSkb {
		delete(spec.Programs, "kprobe_skb_1")
		delete(spec.Programs, "kprobe_skb_2")
		delete(spec.Programs, "kprobe_skb_3")
		delete(spec.Programs, "kprobe_skb_4")
		delete(spec.Programs, "kprobe_skb_5")
		delete(spec.Programs, "kprobe_kfree_skb_reason")
	}
	if !f.FilterSkbDropStack {
		delete(spec.Programs, "kprobe_kfree_skb")
	}

	if !f.FilterTraceSk {
		delete(spec.Programs, "kprobe_sk_1")
		delete(spec.Programs, "kprobe_sk_2")
		delete(spec.Programs, "kprobe_sk_3")
		delete(spec.Programs, "kprobe_sk_4")
		delete(spec.Programs, "kprobe_sk_5")
	}
}
