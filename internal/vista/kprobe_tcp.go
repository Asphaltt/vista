// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package vista

import (
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	progNameKprobeTcpConnect       = "kprobe_tcp_connect"
	progNameTpTcpSendReset         = "tp_tcp_send_reset"
	progNameTpTcpRecvReset         = "tp_tcp_recv_reset"
	progNameTpInetSockSetState     = "tp_inet_sock_set_state"
	progNameKprobeTcpV4DestroySock = "kprobe_tcp_v4_destroy_sock"
)

type tcpKprober struct {
	links []link.Link
}

func (t *tcpKprober) HaveLinks() bool {
	return len(t.links) > 0
}

func (t *tcpKprober) Close() {
	for _, l := range t.links {
		_ = l.Close()
	}
	t.links = nil
}

func KprobeTCP(coll *ebpf.Collection) *tcpKprober {
	var t tcpKprober

	if kp, err := link.Kprobe("tcp_connect", coll.Programs[progNameKprobeTcpConnect], nil); err != nil {
		log.Fatalf("Opening kprobe tcp_connect: %v", err)
	} else {
		t.links = append(t.links, kp)
	}

	if tp, err := link.Tracepoint("tcp", "tcp_send_reset", coll.Programs[progNameTpTcpSendReset], nil); err != nil {
		log.Fatalf("Opening tracepoint tcp_send_reset: %v", err)
	} else {
		t.links = append(t.links, tp)
	}

	if tp, err := link.Tracepoint("tcp", "tcp_receive_reset", coll.Programs[progNameTpTcpRecvReset], nil); err != nil {
		log.Fatalf("Opening tracepoint tcp_receive_reset: %v", err)
	} else {
		t.links = append(t.links, tp)
	}

	if tp, err := link.Tracepoint("sock", "inet_sock_set_state", coll.Programs[progNameTpInetSockSetState], nil); err != nil {
		log.Fatalf("Opening tracepoint inet_sock_set_state: %v", err)
	} else {
		t.links = append(t.links, tp)
	}

	if kp, err := link.Kprobe("tcp_v4_destroy_sock", coll.Programs[progNameKprobeTcpV4DestroySock], nil); err != nil {
		log.Fatalf("Opening kprobe tcp_v4_destroy_sock: %v", err)
	} else {
		t.links = append(t.links, kp)
	}

	log.Printf("Attached tcp kprobes/tracepoints\n")

	return &t
}
