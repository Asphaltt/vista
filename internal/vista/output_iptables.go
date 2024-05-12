// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package vista

import (
	"fmt"
	"io"
	"time"
	"unsafe"
)

var (
	iptablesVerdictNames = []string{
		"DROP",
		"ACCEPT",
		"STOLEN",
		"QUEUE",
		"REPEAT",
		"STOP",
	}

	iptablesHookNames = []string{
		"PREROUTING",
		"INPUT",
		"FORWARD",
		"OUTPUT",
		"POSTROUTING",
	}
)

func _get(names []string, idx uint32, defaultVal string) string {
	if int(idx) < len(names) {
		return names[idx]
	}

	return defaultVal
}

func hookName(hook uint32) string {
	return _get(iptablesHookNames, hook, fmt.Sprintf("UNK(%d)", hook))
}

func verdictName(verdict uint32) string {
	return _get(iptablesVerdictNames, verdict, fmt.Sprintf("UNK(%d)", verdict))
}

func outputIptables(w io.Writer, ipt *IptablesMeta) {
	pf := "PF_INET"
	if ipt.Pf == 10 {
		pf = "PF_INET6"
	}

	table := nullStr(ipt.Table[:])
	hook := hookName(uint32(ipt.Hook))
	verdict := verdictName(ipt.Verdict)
	cost := time.Duration(ipt.Delay)

	fmt.Fprintf(w, " pf=%s table=%s hook=%s verdict=%s cost=%s", pf, table, hook, verdict, cost)
}

func nullStr(b []byte) string {
	if len(b) == 0 {
		return ""
	}

	i := 0
	for i < len(b) && b[i] != 0 {
		i++
	}
	return unsafe.String(&b[0], i)
}
