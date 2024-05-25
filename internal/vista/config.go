// SPDX-License-Identifier: Apache-2.0
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */
/* Copyright Leon Hwang */

package vista

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Version is the vista version and is set at compile time via LDFLAGS-
var Version string = "version unknown"

const (
	outputFlagIsSet int = iota
	outputFlagTrackSkb
	outputFlagOutputMeta
	outputFlagOutputTuple
	outputFlagOutputSkb
	outputFlagOutputStack
	outputFlagOutputIptables
	outputFlagOutputTCP
	outputFlagOutputSk
	outputFlagPcap
)

type FilterCfg struct {
	FilterNetns   uint32
	FilterSkbMark uint32
	FilterSkMark  uint32
	FilterIfindex uint32

	FilterTCPLifetime uint64

	FilterIPv4    [4]byte
	FilterPortBe  [2]byte
	FilterPort    uint16
	FilterL4Proto uint16

	OutputFlags uint16

	PcapSnapLen uint16
	Pad         uint16
}

func (cfg *FilterCfg) setOutputFlags(idx int) {
	cfg.OutputFlags |= 1 << idx
}

func GetConfig(flags *Flags) (cfg FilterCfg, err error) {
	cfg = FilterCfg{
		FilterSkbMark:     flags.FilterSkbMark,
		FilterSkMark:      flags.FilterSkMark,
		FilterL4Proto:     flags.filterL4prto,
		FilterTCPLifetime: uint64(flags.FilterTCPLifetime.Nanoseconds()),
		PcapSnapLen:       flags.PcapSnaplen,
	}

	outputFlags := []struct {
		b   bool
		idx int
	}{
		{true, outputFlagIsSet},
		{flags.FilterTraceSkb, outputFlagTrackSkb},
		{flags.OutputMeta, outputFlagOutputMeta},
		{flags.OutputTuple, outputFlagOutputTuple},
		{flags.OutputSkb, outputFlagOutputSkb},
		{flags.OutputStack, outputFlagOutputStack},
		{flags.OutputIptables, outputFlagOutputIptables},
		{flags.OutputTCP, outputFlagOutputTCP},
		{flags.OutputSk, outputFlagOutputSk},
		{flags.HavePcap(), outputFlagPcap},
	}
	for _, f := range outputFlags {
		if f.b {
			cfg.setOutputFlags(f.idx)
		}
	}

	if flags.FilterPort != 0 {
		cfg.FilterPort = flags.FilterPort
		binary.BigEndian.PutUint16(cfg.FilterPortBe[:], flags.FilterPort)
	}

	if flags.FilterAddr != "" {
		var addr netip.Addr
		addr, err = netip.ParseAddr(flags.FilterAddr)
		if err != nil {
			err = fmt.Errorf("failed to parse IP address %s: %w", flags.FilterAddr, err)
			return
		}

		cfg.FilterIPv4 = addr.As4()
	}

	netnsID, ns, err := parseNetns(flags.FilterNetns)
	if err != nil {
		err = fmt.Errorf("failed to retrieve netns %s: %w", flags.FilterNetns, err)
		return
	}
	if flags.FilterIfname != "" || flags.FilterNetns != "" {
		cfg.FilterNetns = netnsID
	}
	if cfg.FilterIfindex, err = parseIfindex(flags.FilterIfname, ns); err != nil {
		return
	}

	return
}

func parseNetns(netnsSpecifier string) (netnsID uint32, ns netns.NsHandle, err error) {
	switch {
	case netnsSpecifier == "":
		ns, err = netns.Get()
	case strings.HasPrefix(netnsSpecifier, "/"):
		ns, err = netns.GetFromPath(netnsSpecifier)
	case strings.HasPrefix(netnsSpecifier, "inode:"):
		var netnsInode int
		netnsInode, err = strconv.Atoi(netnsSpecifier[6:])
		netnsID = uint32(netnsInode)
	default:
		err = fmt.Errorf("invalid netns specifier: %s", netnsSpecifier)
	}
	if ns == 0 || err != nil {
		return
	}
	var s unix.Stat_t
	if err = unix.Fstat(int(ns), &s); err != nil {
		return
	}
	return uint32(s.Ino), ns, nil
}

func parseIfindex(ifname string, ns netns.NsHandle) (ifindex uint32, err error) {
	if ifname == "" {
		return
	}
	if ns == 0 {
		return 0, fmt.Errorf("inode netns specifier cannot be used with --filter-ifname")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	currentNetns, err := netns.Get()
	if err != nil {
		return
	}
	defer netns.Set(currentNetns)

	if err = netns.Set(ns); err != nil {
		return
	}

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return
	}
	return uint32(iface.Index), nil
}
