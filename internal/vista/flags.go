// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package vista

import (
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
	"time"

	flag "github.com/spf13/pflag"
	"golang.org/x/sys/unix"
)

const (
	outputTimestampNone     = 0
	outputTimestampAbsolute = 1
	outputTimestampRelative = 2
)

type Flags struct {
	ShowVersion bool
	ShowHelp    bool

	KernelBTF string

	FilterTraceSkb      bool
	FilterTraceSk       bool
	FilterTraceIptables bool
	FilterTraceTCP      bool
	FilterTrackSkb      bool
	FilterTraceTc       bool
	FilterTraceXdp      bool

	FilterNetns       string
	FilterSkbMark     uint32
	FilterSkMark      uint32
	FilterSkbFunc     string
	FilterSkFunc      string
	FilterIfname      string
	FilterPcap        string
	FilterKprobeBatch uint

	FilterProto  string
	filterL4prto uint16

	FilterAddr string
	filterAddr netip.Addr
	FilterPort uint16

	FilterTCPLifetime time.Duration

	OutputTS         string
	outputTs         int
	OutputMeta       bool
	OutputTuple      bool
	OutputSkb        bool
	OutputStack      bool
	OutputIptables   bool
	OutputTCP        bool
	OutputSk         bool
	OutputLimitLines int64
	OutputFile       string

	PcapFile    string
	PcapSnaplen uint16
	PcapMode    []string

	FilterSkbDropStack bool

	KMods    []string
	AllKMods bool

	ReadyFile string

	KprobeBackend string

	PerCPUBuffer uint
}

func (f *Flags) SetFlags() {
	flag.BoolVarP(&f.ShowHelp, "help", "h", false, "display this message and exit")
	flag.BoolVar(&f.ShowVersion, "version", false, "show vista version and exit")
	flag.StringVar(&f.KernelBTF, "kernel-btf", "", "specify kernel BTF file")
	flag.StringSliceVar(&f.KMods, "kmods", nil, "list of kernel modules names to attach to")
	flag.BoolVar(&f.AllKMods, "all-kmods", false, "attach to all available kernel modules")

	flag.BoolVar(&f.FilterTraceSkb, "filter-trace-skb", false, "trace skb")
	flag.BoolVar(&f.FilterTraceSk, "filter-trace-sk", false, "trace sock")
	flag.BoolVar(&f.FilterTraceIptables, "filter-trace-iptables", false, "trace iptables")
	flag.BoolVar(&f.FilterTraceTCP, "filter-trace-tcp", false, "trace tcp socket lifetime")
	flag.BoolVar(&f.FilterTrackSkb, "filter-track-skb", false, "trace a packet even if it does not match given filters (e.g., after NAT or tunnel decapsulation)")
	flag.BoolVar(&f.FilterTraceTc, "filter-trace-tc", false, "trace TC bpf progs")
	flag.BoolVar(&f.FilterTraceXdp, "filter-trace-xdp", false, "trace XDP bpf progs")

	flag.StringVar(&f.FilterSkbFunc, "filter-skb-func", "", "filter kernel skb functions to be probed by name (exact match, supports RE2 regular expression)")
	flag.StringVar(&f.FilterSkFunc, "filter-sk-func", "", "filter kernel sk functions to be probed by name (exact match, supports RE2 regular expression)")
	flag.StringVar(&f.FilterNetns, "filter-netns", "", "filter netns (\"/proc/<pid>/ns/net\", \"inode:<inode>\")")
	flag.Uint32Var(&f.FilterSkbMark, "filter-skb-mark", 0, "filter skb mark")
	flag.Uint32Var(&f.FilterSkMark, "filter-sk-mark", 0, "filter sk mark")

	flag.StringVar(&f.FilterIfname, "filter-ifname", "", "filter skb ifname in --filter-netns (if not specified, use current netns)")
	flag.UintVar(&f.FilterKprobeBatch, "filter-kprobe-batch", 10, "batch size for kprobe attaching/detaching")
	flag.StringVar(&f.OutputTS, "timestamp", "none", "print timestamp per event (\"relative\", \"absolute\", \"none\")")
	flag.BoolVar(&f.OutputMeta, "output-meta", false, "print skb metadata")
	flag.BoolVar(&f.OutputTuple, "output-tuple", false, "print L4 tuple")
	flag.BoolVar(&f.OutputStack, "output-stack", false, "print stack")
	flag.Int64Var(&f.OutputLimitLines, "output-limit-lines", 0, "exit the program after the number of events has been received/printed")

	flag.BoolVar(&f.FilterSkbDropStack, "filter-skb-drop-stack", false, "trace kfree_skb and print skb drop stack")

	flag.StringVar(&f.OutputFile, "output-file", "", "write traces to file")

	flag.StringVar(&f.PcapFile, "pcap-file", "", "write packets to pcap file, only work with --filter-trace-xdp/--filter-trace-tc")
	flag.Uint16Var(&f.PcapSnaplen, "pcap-snaplen", 256, "snapture length of packet for pcap")
	flag.StringSliceVar(&f.PcapMode, "pcap-mode", nil, "pcap mode, can be 'entry' and/or 'exit', only work with --pcap-file. Default is 'entry' and 'exit'. 'entry' is to capture packet before BPF prog, 'exit' is to capture packet after BPF prog.")

	flag.StringVar(&f.ReadyFile, "ready-file", "", "create file after all BPF progs are attached")
	flag.Lookup("ready-file").Hidden = true

	flag.StringVar(&f.KprobeBackend, "kprobe-backend", "",
		fmt.Sprintf("Tracing backend('%s', '%s'). Will auto-detect if not specified.", BackendKprobe, BackendKprobeMulti))

	flag.UintVar(&f.PerCPUBuffer, "output-percpu-buffer", 8192, "specified the buffer size for perf-event")

	flag.StringVar(&f.FilterProto, "filter-protocol", "", "filter protocol, tcp, udp, icmp, empty for any")
	flag.StringVar(&f.FilterAddr, "filter-addr", "", "filter IP address")
	flag.Uint16Var(&f.FilterPort, "filter-port", 0, "filter port")

	flag.BoolVar(&f.OutputSkb, "output-skb", false, "print skb")
	flag.BoolVar(&f.OutputSk, "output-sk", false, "print sock")
	flag.BoolVar(&f.OutputIptables, "output-iptables", false, "print iptables")
	flag.BoolVar(&f.OutputTCP, "output-tcp", false, "print TCP")

	flag.DurationVar(&f.FilterTCPLifetime, "filter-tcp-lifetime", 0, "filter TCP lifetime greater than or equal to the given duration (e.g., 100ms, 1s, 1m)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] [pcap-filter]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "    Available pcap-filter: see \"man 7 pcap-filter\"\n")
		fmt.Fprintf(os.Stderr, "    Available options:\n")
		flag.PrintDefaults()
	}
}

func (f *Flags) PrintHelp() {
	flag.Usage()
}

func (f *Flags) Parse() {
	flag.Parse()
	f.FilterPcap = strings.Join(flag.Args(), " ")

	if f.FilterAddr != "" {
		addr, err := netip.ParseAddr(f.FilterAddr)
		if err != nil {
			log.Fatalf("Failed to parse IP address(%s): %v", f.FilterAddr, err)
		}

		f.filterAddr = addr
	}

	switch f.OutputTS {
	case "absolute":
		f.outputTs = outputTimestampAbsolute
	case "relative":
		f.outputTs = outputTimestampRelative
	case "none":
		f.outputTs = outputTimestampNone
	default:
		log.Fatalf("Invalid timestamp: %s", f.OutputTS)
	}

	protocol := strings.ToLower(f.FilterProto)
	if protocol != "" {
		switch protocol {
		case "tcp":
			f.filterL4prto = unix.IPPROTO_TCP
		case "udp":
			f.filterL4prto = unix.IPPROTO_UDP
		case "icmp":
			f.filterL4prto = unix.IPPROTO_ICMP
		default:
			log.Fatalf("Invalid protocol: %s", f.FilterProto)
		}
	}

	if (f.FilterAddr != "" || f.FilterPort != 0 || protocol != "") && f.FilterPcap != "" {
		log.Fatalf("pcap filter cannot be used with --filter-addr or --filter-port or --filter-protocol")
	}

	if protocol == "icmp" && f.FilterPort != 0 {
		log.Fatalf("port can only be used with tcp or udp protocol")
	}

	if f.FilterPcap == "" {
		var filterHost string
		var filterProto string

		if f.FilterAddr != "" {
			filterHost = fmt.Sprintf("host %s", f.FilterAddr)
		}

		if f.FilterPort != 0 {
			if protocol == "tcp" || protocol == "udp" {
				filterProto = fmt.Sprintf("%s port %d", protocol, f.FilterPort)
			} else {
				filterProto = fmt.Sprintf("tcp port %d or udp port %d", f.FilterPort, f.FilterPort)
			}
		} else if protocol != "" {
			filterProto = protocol
		}

		if filterHost != "" && filterProto != "" {
			f.FilterPcap = fmt.Sprintf("%s and %s", filterHost, filterProto)
		} else if filterHost != "" {
			f.FilterPcap = filterHost
		} else if filterProto != "" {
			f.FilterPcap = filterProto
		}
	}

	if f.OutputLimitLines < 0 {
		log.Fatalf("Invalid --output-limit-lines(%d), cannot be < 0", f.OutputLimitLines)
	}

	if f.PcapFile != "" && (!f.FilterTraceXdp && !f.FilterTraceTc) {
		log.Fatal("--pcap-file can only be used with --filter-trace-xdp and/or --filter-trace-tc")
	}

	if f.PcapFile != "" {
		if f.PcapSnaplen < (14 + 20) {
			log.Fatalf("Invalid --filter-snap-len(%d), cannot be < 34", f.PcapSnaplen)
		}

		for _, mode := range f.PcapMode {
			if mode != pcapModeEntry && mode != pcapModeExit {
				log.Fatalf("Invalid --pcap-mode(%s), can only be 'entry' and/or 'exit'", strings.Join(f.PcapMode, ","))
			}
		}

		if len(f.PcapMode) == 0 {
			f.PcapMode = []string{pcapModeEntry, pcapModeExit}
		}
	}

	if f.FilterTCPLifetime < 0 {
		log.Fatalf("Invalid --filter-tcp-lifetime(%s), cannot be < 0s", f.FilterTCPLifetime)
	}
	if 0 < f.FilterTCPLifetime && f.FilterTCPLifetime < time.Millisecond {
		log.Printf("Warning: --filter-tcp-lifetime(%s) is too small and meaningless to filter tcp socket", f.FilterTCPLifetime)
	}
}

func (f *Flags) HavePcap() bool {
	return f.PcapFile != "" && (f.FilterTraceSkb || f.FilterTraceXdp)
}
