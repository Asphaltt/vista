// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Leon Hwang.

package vista

import (
	"fmt"
	"unsafe"
)

type OutputEvent struct {
	Event  *Event
	Packet []byte
	IsPcap bool
}

func NewOutputEvent(raw []byte) (OutputEvent, error) {
	if len(raw) == 0 {
		return OutputEvent{}, fmt.Errorf("empty packet")
	}

	event := (*Event)(unsafe.Pointer(&raw[0]))
	isPcap := event.Source == eventSourcePcap

	size := sizeofEvent
	if isPcap {
		size = sizeofPcapEvent
	}

	if len(raw) < size {
		return OutputEvent{}, fmt.Errorf("record too short: %d < %d", len(raw), size)
	}

	if !isPcap {
		return OutputEvent{Event: event}, nil
	}

	data := raw[size:]
	capLen := event.Pcap().CapLen
	if len(data) < int(capLen) {
		return OutputEvent{}, fmt.Errorf("packet data too short: %d < %d", len(data), capLen)
	}

	data = data[:capLen]

	return OutputEvent{Event: event, Packet: data, IsPcap: true}, nil
}
