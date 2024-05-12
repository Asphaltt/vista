// SPDX-License-Identifier: Apache-2.0
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */
/* Copyright Leon Hwang */

package vista

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/jsimonetti/rtnetlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

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
)

type output struct {
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
}

func NewOutput(flags *Flags, printSkbMap *ebpf.Map, printStackMap *ebpf.Map,
	addr2Name Addr2Name, kprobeMulti bool, btfSpec *btf.Spec,
) (*output, error) {
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
	if flags.OutputMeta {
		ifs, err = getIfaces()
		if err != nil {
			log.Printf("Failed to retrieve all ifaces from all network namespaces: %v. Some iface names might be not shown.", err)
		}
	}

	return &output{
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
	}, nil
}

func (o *output) Close() {
	if o.writer != os.Stdout {
		_ = o.writer.Sync()
		_ = o.writer.Close()
	}
}

func (o *output) PrintHeader() {
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

func (o *output) Print(event *Event) {
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
			outputIptables(o.buf, event.Iptables())
		}
	case eventSourceTCP:
		if o.flags.OutputTCP {
			outputTCP(o.buf, event.TCP())
		}
	case eventSourceSk:
		if o.flags.OutputSk {
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

	fmt.Fprintln(o.writer, o.buf.String())

	o.buf.Reset()
}

func pktTypeToStr(pktType uint8) string {
	// See: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_packet.h#L26
	const (
		PACKET_USER   = 6
		PACKET_KERNEL = 7
	)
	pktTypes := []string{
		syscall.PACKET_HOST:      "HOST",
		syscall.PACKET_BROADCAST: "BROADCAST",
		syscall.PACKET_MULTICAST: "MULTICAST",
		syscall.PACKET_OTHERHOST: "OTHERHOST",
		syscall.PACKET_OUTGOING:  "OUTGOING",
		syscall.PACKET_LOOPBACK:  "LOOPBACK",
		PACKET_USER:              "USER",
		PACKET_KERNEL:            "KERNEL",
	}
	if pktType <= PACKET_KERNEL {
		return pktTypes[pktType]
	}
	return fmt.Sprintf("UNK(%d)", pktType)
}

func (o *output) getIfaceName(netnsInode, ifindex uint32) string {
	if ifaces, ok := o.ifaceCache[uint64(netnsInode)]; ok {
		if name, ok := ifaces[ifindex]; ok {
			return fmt.Sprintf("%d(%s)", ifindex, name)
		}
	}
	return strconv.Itoa(int(ifindex))
}

func getIfaces() (map[uint64]map[uint32]string, error) {
	var err error
	procPath := "/proc"

	ifaceCache := make(map[uint64]map[uint32]string)

	dirs, err := os.ReadDir(procPath)
	if err != nil {
		return nil, err
	}

	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}

		// skip non-process dirs
		if _, err := strconv.Atoi(d.Name()); err != nil {
			continue
		}

		// get inode of netns
		path := filepath.Join(procPath, d.Name(), "ns", "net")
		fd, err0 := os.Open(path)
		if err0 != nil {
			err = errors.Join(err, err0)
			continue
		}
		var stat unix.Stat_t
		if err0 := unix.Fstat(int(fd.Fd()), &stat); err0 != nil {
			err = errors.Join(err, err0)
			continue
		}
		inode := stat.Ino

		if _, exists := ifaceCache[inode]; exists {
			continue // we already checked that netns
		}

		ifaces, err0 := getIfacesInNetNs(path)
		if err0 != nil {
			err = errors.Join(err, err0)
			continue
		}

		ifaceCache[inode] = ifaces

	}

	return ifaceCache, err
}

func getIfacesInNetNs(path string) (map[uint32]string, error) {
	current, err := netns.Get()
	if err != nil {
		return nil, err
	}

	remote, err := netns.GetFromPath(path)
	if err != nil {
		return nil, err
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := netns.Set(remote); err != nil {
		return nil, err
	}

	defer netns.Set(current)

	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	msg, err := conn.Link.List()
	if err != nil {
		return nil, err
	}

	ifaces := make(map[uint32]string)
	for _, link := range msg {
		ifaces[link.Index] = link.Attributes.Name
	}

	return ifaces, nil
}
