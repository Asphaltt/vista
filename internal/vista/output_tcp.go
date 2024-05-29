// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package vista

import (
	"fmt"
	"io"
	"time"
)

type Reset uint8

func (r Reset) String() string {
	switch r {
	case 1:
		return "SEND"
	case 2:
		return "RECV"
	default:
		return "-"
	}
}

type Bytes uint64

func (b Bytes) String() string {
	if b < 1<<10 {
		return fmt.Sprintf("%dB", b)
	}

	if b < 1<<20 {
		f := float64(b) / (1 << 10)
		return fmt.Sprintf("%.3fKiB", f)
	}

	if b < 1<<30 {
		f := float64(b) / (1 << 20)
		return fmt.Sprintf("%.3fMiB", f)
	}

	if b < 1<<40 {
		f := float64(b) / (1 << 30)
		return fmt.Sprintf("%.3fGiB", f)
	}

	if b < 1<<50 {
		f := float64(b) / (1 << 40)
		return fmt.Sprintf("%.3fTeB", f)
	}

	f := float64(b) / (1 << 50)
	return fmt.Sprintf("%.3fPeB", f)
}

func outputTCP(w io.Writer, tcp *TCPMeta) {
	fmt.Fprintf(w, " rx=%s tx=%s lifetime=%s srtt=%s retrans=%d sk_mark=%#x cong=%s",
		tcp.RxBytes, tcp.TxBytes, time.Nanosecond*time.Duration(tcp.Lifetime),
		time.Microsecond*time.Duration(tcp.Srtt), tcp.Retrans, tcp.SkMark,
		nullStr(tcp.Cong[:]))
	if tcp.Reset != 0 {
		fmt.Fprintf(w, " reset=%d", tcp.Reset)
	}
}
