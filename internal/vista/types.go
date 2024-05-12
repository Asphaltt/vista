// SPDX-License-Identifier: Apache-2.0
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */
/* Copyright Leon Hwang */

package vista

import (
	"unsafe"
)

const (
	MaxStackDepth = 50

	BackendKprobe      = "kprobe"
	BackendKprobeMulti = "kprobe-multi"
)

type PortInfo struct {
	Sport uint16
	Dport uint16
}

type ICMPInfo struct {
	ID   uint16
	Seq  uint16
	Type uint8
	Pad  [3]uint8
}

type Tuple struct {
	Saddr   [16]byte
	Daddr   [16]byte
	L3Proto uint16
	L4Proto uint8
	Pad     uint8
	Data    [8]byte
}

func (t *Tuple) PortInfo() *PortInfo {
	return (*PortInfo)(unsafe.Pointer(&t.Data[0]))
}

func (t *Tuple) ICMPInfo() *ICMPInfo {
	return (*ICMPInfo)(unsafe.Pointer(&t.Data[0]))
}

type Meta struct {
	Netns   uint32
	Mark    uint32
	Ifindex uint32
	Len     uint32
	MTU     uint32
	Proto   uint16
	PktType uint8

	IsKfreeSkbReason uint8
	KfreeSkbReason   uint32
}

type StackData struct {
	IPs [MaxStackDepth]uint64
}

type IptablesMeta struct {
	Table   [32]byte
	Delay   uint64
	Verdict uint32
	Hook    uint8
	Pf      uint8
	Pad     [2]byte
}

type TCPMeta struct {
	RxBytes  Bytes
	TxBytes  Bytes
	Lifetime uint64 // in ns
	Srtt     uint32 // in us
	Retrans  uint32
	SkMark   uint32
	Reset    uint8
	Pad      [3]byte
	Cong     [16]byte
	Comm     [16]byte
}

type SockMeta struct {
	SkcBoundIfindex uint32
	// SkRxDstIfindex  uint32
	SkBacklog       uint32
	SkRcvBuff       uint32
	SkSndBuff       uint32
	SkPriority      uint32
	SkMark          uint32
	SkType          sockType
	SocketState     socketState
	SkcState        sockState
	SkcReusePort    uint8
	WithSocket      uint8
	SocketPad       uint8
	SocketFileInode uint64
	SocketFlags     uint64
}

const (
	sizeofIptablesMeta = int(unsafe.Sizeof(IptablesMeta{})) // 48
	sizeofTCPMeta      = int(unsafe.Sizeof(TCPMeta{}))      // 72
	sizeofSockMeta     = int(unsafe.Sizeof(SockMeta{}))     // 48
)

type Event struct {
	PID          uint32
	Type         uint8
	Source       uint8
	Pad          uint16
	Addr         uint64
	SAddr        uint64
	Timestamp    uint64
	PrintSkbId   uint64
	Meta         Meta
	Tuple        Tuple
	PrintStackId int64
	CPU          uint32
	Data         [72]byte
}

func (e *Event) Iptables() *IptablesMeta {
	return (*IptablesMeta)(unsafe.Pointer(&e.Data[0]))
}

func (e *Event) TCP() *TCPMeta {
	return (*TCPMeta)(unsafe.Pointer(&e.Data[0]))
}

func (e *Event) Sock() *SockMeta {
	return (*SockMeta)(unsafe.Pointer(&e.Data[0]))
}
