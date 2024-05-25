// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Leon Hwang.

package vista

import (
	"fmt"
	"syscall"
)

func pktTypeToStr(pktType uint8) string {
	// See: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_packet.h#L26
	const (
		PACKET_USER   = 6
		PACKET_KERNEL = 7
	)
	pktTypes := []string{
		syscall.PACKET_HOST:      "HOST",
		syscall.PACKET_BROADCAST: "BROADCAST",
		syscall.PACKET_MULTICAST: "MULTICAST",
		syscall.PACKET_OTHERHOST: "OTHERHOST",
		syscall.PACKET_OUTGOING:  "OUTGOING",
		syscall.PACKET_LOOPBACK:  "LOOPBACK",
		PACKET_USER:              "USER",
		PACKET_KERNEL:            "KERNEL",
	}
	if pktType <= PACKET_KERNEL {
		return pktTypes[pktType]
	}
	return fmt.Sprintf("UNK(%d)", pktType)
}
