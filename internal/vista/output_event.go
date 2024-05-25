// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Leon Hwang.

package vista

import (
	"fmt"
	"unsafe"

	"golang.org/x/sync/errgroup"
)

type OutputEvent struct {
	Event  *Event
	Packet []byte
	IsPcap bool
}

func NewOutputEvent(raw []byte, isPcap bool) (OutputEvent, error) {
	if len(raw) == 0 {
		return OutputEvent{}, fmt.Errorf("empty packet")
	}

	size := sizeofEvent
	if isPcap {
		size = sizeofPcapEvent
	}

	if len(raw) < size {
		return OutputEvent{}, fmt.Errorf("record too short: %d < %d", len(raw), size)
	}

	event := (*Event)(unsafe.Pointer(&raw[0]))

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

type EventChannels struct {
	chs []chan OutputEvent

	out chan OutputEvent
}

func NewEventChannels(chs ...chan OutputEvent) *EventChannels {
	e := &EventChannels{
		chs: chs,
		out: make(chan OutputEvent, 100),
	}

	go e.run()

	return e
}

func (e *EventChannels) RecvChan() <-chan OutputEvent {
	return e.out
}

func (e *EventChannels) Drain() {
	for range e.out {
	}
}

func (e *EventChannels) runChan(ch chan OutputEvent) {
	for ev := range ch {
		e.out <- ev
	}
}

func (e *EventChannels) run() {
	var errg errgroup.Group

	for _, ch := range e.chs {
		ch := ch
		errg.Go(func() error {
			e.runChan(ch)
			return nil
		})
	}

	_ = errg.Wait()

	close(e.out)
}
