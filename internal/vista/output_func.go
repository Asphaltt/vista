// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package vista

import (
	"fmt"
	"runtime"
)

func (o *Output) getFuncName(event *Event) string {
	var outFuncName string

	switch event.Source {
	case eventSourceSkb, eventSourceSk:
		var addr uint64
		// XXX: not sure why the -1 offset is needed on x86 but not on arm64
		switch runtime.GOARCH {
		case "amd64":
			addr = event.Addr
			if !o.kprobeMulti {
				addr -= 1
			}
		case "arm64":
			addr = event.Addr
		}

		var funcName string
		if ksym, ok := o.addr2name.Addr2NameMap[addr]; ok {
			funcName = ksym.name
		} else if ksym, ok := o.addr2name.Addr2NameMap[addr-4]; runtime.GOARCH == "amd64" && ok {
			// Assume that function has ENDBR in its prelude (enabled by CONFIG_X86_KERNEL_IBT).
			// See https://lore.kernel.org/bpf/20220811091526.172610-5-jolsa@kernel.org/
			// for more ctx.
			funcName = ksym.name
		} else {
			funcName = fmt.Sprintf("0x%x", addr)
		}

		if event.Type != eventTypeKprobe {
			switch event.Type {
			case eventTypeTracingTc:
				funcName += "(tc)"
			case eventTypeTracingXdp:
				funcName += "(xdp)"
			}
		}

		outFuncName = funcName
		if event.Meta.IsKfreeSkbReason != 0 {
			reason := kfreeSkbReasonToStr(event.Meta.KfreeSkbReason, o.kfreeReasons)
			outFuncName = fmt.Sprintf("%s(%s)", funcName, reason)
		}

	case eventSourceIptables:
		outFuncName = "ipt_do_table"

	case eventSourceTCP:
		outFuncName = "TCP"
	}

	return outFuncName
}
