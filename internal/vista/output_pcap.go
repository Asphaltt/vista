// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Leon Hwang.

package vista

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type pcapWriter struct {
	fd  *os.File
	w   *pcapgo.Writer
	ngw *pcapgo.NgWriter
}

func newPcapWriter(pcapFile, pcapFilter string, snapLen uint16) (*pcapWriter, error) {
	fd, err := os.OpenFile(pcapFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", pcapFile, err)
	}

	ext := filepath.Ext(pcapFile)
	isPcapng := ext == ".pcapng"

	if !isPcapng {
		w := pcapgo.NewWriter(fd)
		w.WriteFileHeader(uint32(snapLen), layers.LinkTypeEthernet)
		return &pcapWriter{fd: fd, w: w}, nil
	}

	name := "Captured by VISTA"
	ngIface := pcapgo.NgInterface{
		Name:       name,
		Filter:     pcapFilter,
		LinkType:   layers.LinkTypeEthernet,
		SnapLength: uint32(snapLen),
	}
	ngw, err := pcapgo.NewNgWriterInterface(fd, ngIface, pcapgo.NgWriterOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create pcapng writer: %w", err)
	}

	if err := ngw.Flush(); err != nil {
		return nil, fmt.Errorf("failed to flush pcapng writer: %w", err)
	}

	return &pcapWriter{fd: fd, ngw: ngw}, nil
}

func (p *pcapWriter) close() {
	if p.ngw != nil {
		_ = p.ngw.Flush()
	}

	if p.fd != nil {
		_ = p.fd.Sync()
		_ = p.fd.Close()
	}
}

func (p *pcapWriter) meta2options(ev *Event, meta *PcapMeta, iface string) []pcapgo.NgOption {
	var opts []pcapgo.NgOption

	info := map[string]string{}

	isFexit := meta.IsFexit == 1
	if isFexit {
		info["tracing"] = "fexit"
	} else {
		info["tracing"] = "fentry"
	}

	isXdp := ev.Type == eventTypeTracingXdp
	if isXdp {
		info["bpf"] = "xdp"
	} else {
		info["bpf"] = "tc"
	}

	if isFexit {
		action := meta.Action
		if isXdp {
			info["action"] = xdpAction(action).Action()
		} else {
			info["action"] = tcAction(action).Action()
		}
	}

	if iface != "" {
		info["iface"] = iface
	}

	data, _ := json.Marshal(info)
	comment := string(data)
	opts = append(opts, pcapgo.NewOptionComment(comment))

	if isFexit {
		// Ref:
		// https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#section-4.3-19.2.1
		//
		// The verdict type can be: Hardware (type octet = 0, size = variable),
		// Linux_eBPF_TC (type octet = 1, size = 8 (64-bit unsigned integer),
		// value = TC_ACT_* as defined in the Linux pck_cls.h include),
		// Linux_eBPF_XDP (type octet = 2, size = 8 (64-bit unsigned integer),
		// value = xdp_action as defined in the Linux pbf.h include).
		verdict := [9]byte{}
		if isXdp {
			verdict[0] = 2
		} else {
			verdict[0] = 1
		}
		binary.NativeEndian.PutUint64(verdict[1:], uint64(meta.Action))

		opts = append(opts, pcapgo.NewOptionEnhancedPacketVerdict(verdict[:]))
	}

	opts = append(opts, pcapgo.NewOptionEnhancedPacketQueueID(meta.RxQueue))

	return opts
}

func (p *pcapWriter) writePacket(ev OutputEvent, iface string) error {
	meta := ev.Event.Pcap()

	info := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: int(meta.CapLen),
		Length:        int(ev.Event.Meta.Len),
	}

	var err error
	if p.ngw != nil {
		opts := p.meta2options(ev.Event, meta, iface)
		err = p.ngw.WritePacket(info, ev.Packet, opts...)
	} else {
		err = p.w.WritePacket(info, ev.Packet)
	}
	if err != nil {
		return fmt.Errorf("failed to write packet: %w", err)
	}

	if p.ngw != nil {
		err := p.ngw.Flush()
		if err != nil {
			return fmt.Errorf("failed to flush pcapng writer: %w", err)
		}
	}

	return nil
}
