// SPDX-License-Identifier: Apache-2.0
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */
/* Copyright Leon Hwang */

package vista

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/Asphaltt/vista/internal/byteorder"
)

const absoluteTS string = "15:04:05.000"

const (
	eventTypeKprobe     = 0
	eventTypeTracingTc  = 1
	eventTypeTracingXdp = 2

	eventSourceSkb      = 0
	eventSourceSk       = 1
	eventSourceIptables = 2
	eventSourceTCP      = 3
	eventSourcePcap     = 4
)

type Output struct {
	flags         *Flags
	lastSeenSkb   map[uint64]uint64 // skb addr => last seen TS
	printSkbMap   *ebpf.Map
	printStackMap *ebpf.Map
	addr2name     Addr2Name
	writer        *os.File
	buf           *bytes.Buffer
	kprobeMulti   bool
	kfreeReasons  map[uint32]string
	ifaceCache    map[uint64]map[uint32]string
	pcap          *pcapWriter
}

func NewOutput(flags *Flags, printSkbMap *ebpf.Map, printStackMap *ebpf.Map,
	addr2Name Addr2Name, kprobeMulti bool, btfSpec *btf.Spec,
) (*Output, error) {
	writer := os.Stdout

	if flags.OutputFile != "" {
		file, err := os.Create(flags.OutputFile)
		if err != nil {
			return nil, err
		}
		writer = file
	}

	reasons, err := getKFreeSKBReasons(btfSpec)
	if err != nil {
		log.Printf("Unable to load packet drop reaons: %v", err)
	}

	var ifs map[uint64]map[uint32]string
	if flags.OutputMeta || flags.HavePcap() {
		ifs, err = getIfaces()
		if err != nil {
			log.Printf("Failed to retrieve all ifaces from all network namespaces: %v. Some iface names might be not shown.", err)
		}
	}

	var pcap *pcapWriter
	if flags.HavePcap() {
		pcap, err = newPcapWriter(flags.PcapFile, flags.FilterPcap, flags.PcapSnaplen)
		if err != nil {
			return nil, err
		}
	}

	return &Output{
		flags:         flags,
		lastSeenSkb:   map[uint64]uint64{},
		printSkbMap:   printSkbMap,
		printStackMap: printStackMap,
		addr2name:     addr2Name,
		writer:        writer,
		buf:           bytes.NewBuffer(make([]byte, 0, 256)),
		kprobeMulti:   kprobeMulti,
		kfreeReasons:  reasons,
		ifaceCache:    ifs,
		pcap:          pcap,
	}, nil
}

func (o *Output) Close() {
	if o.writer != os.Stdout {
		_ = o.writer.Sync()
		_ = o.writer.Close()
	}

	if o.pcap != nil {
		o.pcap.close()
	}
}

func (o *Output) PrintHeader() {
	if o.flags.outputTs == outputTimestampAbsolute {
		fmt.Fprintf(o.buf, "%12s ", "TIME")
	}
	fmt.Fprintf(o.buf, "%18s %6s %16s %24s", "SKB/SK", "CPU", "PROCESS", "FUNC")
	if o.flags.outputTs != outputTimestampNone {
		fmt.Fprintf(o.buf, " %16s", "TIMESTAMP")
	}
	fmt.Fprintf(o.buf, "\n")

	fmt.Fprint(o.writer, o.buf.String())

	o.buf.Reset()
}

func (o *Output) print(event *Event) {
	if o.flags.outputTs == outputTimestampAbsolute {
		fmt.Fprintf(o.buf, "%12s ", time.Now().Format(absoluteTS))
	}
	ts := event.Timestamp
	if o.flags.outputTs == outputTimestampRelative {
		if last, found := o.lastSeenSkb[event.SAddr]; found {
			ts = ts - last
		} else {
			ts = 0
		}
	}

	outFuncName := o.getFuncName(event)
	execName := o.getProcessExecName(event)
	fmt.Fprintf(o.buf, "%18s %6s %16s %24s", fmt.Sprintf("%#x", event.SAddr),
		fmt.Sprintf("%d", event.CPU), fmt.Sprintf("[%s]", execName), outFuncName)
	if o.flags.outputTs != outputTimestampNone {
		fmt.Fprintf(o.buf, " %16d", ts)
	}
	o.lastSeenSkb[event.SAddr] = event.Timestamp

	if o.flags.OutputMeta {
		fmt.Fprintf(o.buf, " netns=%d mark=%#x iface=%s proto=%#04x mtu=%d len=%d pkt_type=%s",
			event.Meta.Netns, event.Meta.Mark,
			o.getIfaceName(event.Meta.Netns, event.Meta.Ifindex),
			byteorder.NetworkToHost16(event.Meta.Proto), event.Meta.MTU,
			event.Meta.Len, pktTypeToStr(event.Meta.PktType))
	}

	if o.flags.OutputTuple {
		outputTuple(o.buf, &event.Tuple)
	}

	switch event.Source {
	case eventSourceIptables:
		if o.flags.OutputIptables {
			fmt.Fprintf(o.buf, "\nIPTABLES:")
			outputIptables(o.buf, event.Iptables())
		}
	case eventSourceTCP:
		if o.flags.OutputTCP {
			fmt.Fprintf(o.buf, "\nTCP:")
			outputTCP(o.buf, event.TCP())
		}
	case eventSourceSk:
		if o.flags.OutputSk {
			fmt.Fprintf(o.buf, "\nSOCK:")
			outputSock(o.buf, event.Sock())
		}
	}

	if event.PrintStackId > 0 {
		var stack StackData
		id := uint32(event.PrintStackId)
		if err := o.printStackMap.Lookup(&id, &stack); err == nil {
			for _, ip := range stack.IPs {
				if ip > 0 {
					fmt.Fprintf(o.buf, "\n%s", o.addr2name.findNearestSym(ip))
				}
			}
		}
		_ = o.printStackMap.Delete(&id)
	}

	if o.flags.OutputSkb {
		id := uint32(event.PrintSkbId)
		if str, err := o.printSkbMap.LookupBytes(&id); err == nil {
			fmt.Fprintf(o.buf, "\n%s", string(str))
		}
	}
}

func (o *Output) flushBuffer() {
	fmt.Fprintln(o.writer, o.buf.String())

	o.buf.Reset()
}

func (o *Output) Print(ev OutputEvent) {
	o.print(ev.Event)
	o.flushBuffer()
}

func (o *Output) Pcap(ev OutputEvent) error {
	o.print(ev.Event)
	fmt.Fprintf(o.buf, "\nSaving this packet to %s..", o.flags.PcapFile)
	o.flushBuffer()

	iface := o.getIfaceName(ev.Event.Meta.Netns, ev.Event.Meta.Ifindex)
	if err := o.pcap.writePacket(ev, iface); err != nil {
		return fmt.Errorf("failed to handle packet: %w", err)
	}

	return nil
}
