// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Leon Hwang.

package vista

type (
	xdpAction int
	tcAction  int
)

const (
	xdpAborted xdpAction = iota
	xdpDrop
	xdpPass
	xdpTx
	xdpRedirect
)

// All known XDP actions
var xdpActions = []xdpAction{
	xdpAborted,
	xdpDrop,
	xdpPass,
	xdpTx,
	xdpRedirect,
}

func (a xdpAction) String() string {
	switch a {
	case xdpAborted:
		return "abort"
	case xdpDrop:
		return "drop"
	case xdpPass:
		return "pass"
	case xdpTx:
		return "tx"
	case xdpRedirect:
		return "redirect"
	default:
		return ""
	}
}

func (a xdpAction) Action() string {
	var action string
	switch a {
	case 0:
		action = "XDP_ABORTED"
	case 1:
		action = "XDP_DROP"
	case 2:
		action = "XDP_PASS"
	case 3:
		action = "XDP_TX"
	case 4:
		action = "XDP_REDIRECT"
	default:
		action = "XDP_UNKNOWN"
	}

	return action
}

const (
	tcOK tcAction = iota
	tcReclass
	tcShot
	tcPipe
	tcStolen
	tcQueue
	tcRepeat
	tcRedir
	tcTrap
)

// All known tc actions
var tcActions = []tcAction{
	tcOK,
	tcReclass,
	tcShot,
	tcPipe,
	tcStolen,
	tcQueue,
	tcRepeat,
	tcRedir,
	tcTrap,
}

func (a tcAction) String() string {
	switch a {
	case tcOK:
		return "ok"
	case tcReclass:
		return "reclass"
	case tcShot:
		return "shot"
	case tcPipe:
		return "pipe"
	case tcStolen:
		return "stolen"
	case tcQueue:
		return "queue"
	case tcRepeat:
		return "repeat"
	case tcRedir:
		return "redir"
	case tcTrap:
		return "trap"
	default:
		return ""
	}
}

func (a tcAction) Action() string {
	var action string
	switch a {
	case 0:
		action = "TC_ACT_OK"
	case 1:
		action = "TC_ACT_RECLASSIFY"
	case 2:
		action = "TC_ACT_SHOT"
	case 3:
		action = "TC_ACT_PIPE"
	case 4:
		action = "TC_ACT_STOLEN"
	case 5:
		action = "TC_ACT_QUEUED"
	case 6:
		action = "TC_ACT_REPEAT"
	case 7:
		action = "TC_ACT_REDIRECT"
	case 8:
		action = "TC_ACT_TRAP"
	default:
		action = "TC_ACT_UNKNOWN"
	}

	return action
}
