// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package vista

import (
	"fmt"
	"io"
	"net"
	"syscall"

	"github.com/Asphaltt/vista/internal/byteorder"
	"github.com/cilium/ebpf/btf"
)

func outputTuple(w io.Writer, tuple *Tuple) {
	proto := protoToStr(tuple.L4Proto)
	saddr := addrToStr(tuple.L3Proto, tuple.Saddr)
	daddr := addrToStr(tuple.L3Proto, tuple.Daddr)

	if tuple.L4Proto == syscall.IPPROTO_TCP || tuple.L4Proto == syscall.IPPROTO_UDP {
		l4info := tuple.PortInfo()
		fmt.Fprintf(w, " %s:%d->%s:%d(%s)",
			saddr, byteorder.NetworkToHost16(l4info.Sport),
			daddr, byteorder.NetworkToHost16(l4info.Dport),
			proto)
		return
	}

	if tuple.L4Proto == syscall.IPPROTO_ICMP || tuple.L4Proto == syscall.IPPROTO_ICMPV6 {
		icmpInfo := tuple.ICMPInfo()
		switch icmpInfo.Type {
		case 8, 128:
			fmt.Fprintf(w, " %s->%s(%s request id=%d seq=%d)",
				saddr, daddr, proto, icmpInfo.ID, icmpInfo.Seq)
		case 0, 129:
			fmt.Fprintf(w, " %s->%s(%s reply id=%d seq=%d)",
				saddr, daddr, proto, icmpInfo.ID, icmpInfo.Seq)
		}
		return
	}

	fmt.Fprintf(w, " %s->%s(%s)", saddr, daddr, proto)
}

func protoToStr(proto uint8) string {
	switch proto {
	case syscall.IPPROTO_TCP:
		return "tcp"
	case syscall.IPPROTO_UDP:
		return "udp"
	case syscall.IPPROTO_ICMP:
		return "icmp"
	case syscall.IPPROTO_ICMPV6:
		return "icmp6"
	default:
		return fmt.Sprintf("proto=%d", proto)
	}
}

func addrToStr(proto uint16, addr [16]byte) string {
	switch proto {
	case syscall.ETH_P_IP:
		return net.IP(addr[:4]).String()
	case syscall.ETH_P_IPV6:
		return fmt.Sprintf("[%s]", net.IP(addr[:]).String())
	default:
		return ""
	}
}

// getKFreeSKBReasons dervices SKB drop reasons from the "skb_drop_reason" enum
// defined in /include/net/dropreason.h.
func getKFreeSKBReasons(spec *btf.Spec) (map[uint32]string, error) {
	if _, err := spec.AnyTypeByName("kfree_skb_reason"); err != nil {
		// Kernel is too old to have kfree_skb_reason
		return nil, nil
	}

	var dropReasonsEnum *btf.Enum
	if err := spec.TypeByName("skb_drop_reason", &dropReasonsEnum); err != nil {
		return nil, fmt.Errorf("failed to find 'skb_drop_reason' enum: %v", err)
	}

	ret := map[uint32]string{}
	for _, val := range dropReasonsEnum.Values {
		ret[uint32(val.Value)] = val.Name
	}

	return ret, nil
}

func kfreeSkbReasonToStr(reason uint32, reasons map[uint32]string) string {
	if reasonStr, ok := reasons[reason]; ok {
		return reasonStr
	}
	return fmt.Sprintf(" %d", reason)
}
