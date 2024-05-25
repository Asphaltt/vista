// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package vista

import (
	"fmt"
	"io"
)

type sockType uint16

const (
	SOCK_STREAM    sockType = 1
	SOCK_DGRAM     sockType = 2
	SOCK_RAW       sockType = 3
	SOCK_RDM       sockType = 4
	SOCK_SEQPACKET sockType = 5
	SOCK_DCCP      sockType = 6
	SOCK_PACKET    sockType = 10
)

func (s sockType) String() string {
	types := map[sockType]string{
		SOCK_STREAM:    "SOCK_STREAM",
		SOCK_DGRAM:     "SOCK_DGRAM",
		SOCK_RAW:       "SOCK_RAW",
		SOCK_RDM:       "SOCK_RDM",
		SOCK_SEQPACKET: "SOCK_SEQPACKET",
		SOCK_DCCP:      "SOCK_DCCP",
		SOCK_PACKET:    "SOCK_PACKET",
	}
	return types[s]
}

type socketState uint16

const (
	socketStateFree socketState = iota
	socketStateUnconnected
	socketStateConnecting
	socketStateConnected
	socketStateDisconnecting
)

func (s socketState) String() string {
	switch s {
	case socketStateFree:
		return "FREE"
	case socketStateUnconnected:
		return "UNCONNECTED"
	case socketStateConnecting:
		return "CONNECTING"
	case socketStateConnected:
		return "CONNECTED"
	case socketStateDisconnecting:
		return "DISCONNECTING"
	default:
		return ""
	}
}

type sockState uint8

const (
	TCP_ESTABLISHED sockState = 1 + iota
	TCP_SYN_SENT
	TCP_SYN_RECV
	TCP_FIN_WAIT1
	TCP_FIN_WAIT2
	TCP_TIME_WAIT
	TCP_CLOSE
	TCP_CLOSE_WAIT
	TCP_LAST_ACK
	TCP_LISTEN
	TCP_CLOSING /* Now a valid state */
	TCP_NEW_SYN_RECV
	TCP_BOUND_INACTIVE /* Pseudo-state for inet_diag */
)

func (t sockState) String() string {
	switch t {
	case TCP_ESTABLISHED:
		return "ESTABLISHED"
	case TCP_SYN_SENT:
		return "SYN_SENT"
	case TCP_SYN_RECV:
		return "SYN_RECV"
	case TCP_FIN_WAIT1:
		return "FIN_WAIT1"
	case TCP_FIN_WAIT2:
		return "FIN_WAIT2"
	case TCP_TIME_WAIT:
		return "TIME_WAIT"
	case TCP_CLOSE:
		return "CLOSE"
	case TCP_CLOSE_WAIT:
		return "CLOSE_WAIT"
	case TCP_LAST_ACK:
		return "LAST_ACK"
	case TCP_LISTEN:
		return "LISTEN"
	case TCP_CLOSING:
		return "CLOSING"
	case TCP_NEW_SYN_RECV:
		return "NEW_SYN_RECV"
	case TCP_BOUND_INACTIVE:
		return "BOUND_INACTIVE"
	default:
		return ""
	}
}

func outputSockCommon(w io.Writer, meta *SockMeta) {
	state := sockState(meta.SkcState).String()
	fmt.Fprintf(w, " skc_state=%s skc_reuseport=%v skc_bound_ifindex=%d",
		state, meta.SkcReusePort == 1, meta.SkcBoundIfindex)
}

func outputSockInfo(w io.Writer, meta *SockMeta) {
	typ := sockType(meta.SkType).String()
	fmt.Fprintf(w, " sk_backlog=%d sk_rcv_buff=%d sk_snd_buff=%d sk_priority=%d sk_mark=%#x sk_type=%s",
		meta.SkBacklog, meta.SkRcvBuff, meta.SkSndBuff,
		meta.SkPriority, meta.SkMark, typ)
}

func outputSocketInfo(w io.Writer, meta *SockMeta) {
	state := socketState(meta.SocketState).String()
	fmt.Fprintf(w, " socket_state=%s socket_file_inode=%d socket_flags=%d",
		state, meta.SocketFileInode, meta.SocketFlags)
}

func outputSock(w io.Writer, meta *SockMeta) {
	outputSockCommon(w, meta)
	outputSockInfo(w, meta)
	if meta.WithSocket == 1 {
		fmt.Fprintf(w, "\nSOCKET:")
		outputSocketInfo(w, meta)
	}
}
