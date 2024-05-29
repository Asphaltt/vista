// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package vista

import (
	"fmt"

	"github.com/tklauser/ps"
)

func (o *Output) getProcessExecName(event *Event) string {
	var execName string
	if event.PID != 0 {
		if event.Source != eventSourceTCP {
			p, err := ps.FindProcess(int(event.PID))
			if err == nil && p != nil {
				execName = fmt.Sprintf("%s(%d)", p.ExecutablePath(), event.PID)
			} else {
				execName = fmt.Sprintf("<empty>(%d)", event.PID)
			}
		} else {
			execName = fmt.Sprintf("%s(%d)", nullStr(event.TCP().Comm[:]), event.PID)
		}
	} else {
		execName = "<empty>(0)"
	}

	return execName
}
