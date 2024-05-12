// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package vista

import (
	"log"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/blang/semver/v4"
	"github.com/shirou/gopsutil/v3/host"
)

const (
	iptDoTableGE5_16 = 1
	iptDoTableL5_16  = 2

	progNameKprobeIptDoTable    = "kprobe_ipt_do_table"
	progNameKprobeIptDoTableOld = "kprobe_ipt_do_table_old"
	progNameKretprobeIptDoTable = "kretprobe_ipt_do_table"

	progNameKprobeNfHookSlow = "kprobe_nf_hook_slow"
	progNameKretprobeNfHook  = "kretprobe_nf_hook_slow"
)

type iptablesKprober struct {
	links []link.Link
}

func (t *iptablesKprober) HaveLinks() bool {
	return len(t.links) > 0
}

func (t *iptablesKprober) Close() {
	for _, l := range t.links {
		_ = l.Close()
	}
	t.links = nil
}

func trimReleaseSuffix(release string) string {
	fields := strings.Split(release, ".")
	if len(fields) > 2 {
		l := len(fields)
		if fields[l-1] == "x86_64" && strings.HasPrefix(fields[l-2], "oe") {
			fields = fields[:len(fields)-2]
		}
	}
	return strings.Join(fields, ".")
}

func KprobeIptables(coll *ebpf.Collection) *iptablesKprober {
	var t iptablesKprober

	release, err := host.KernelVersion()
	if err != nil {
		log.Fatalf("Failed to get kernel version: %v\n", err)
	}

	release = trimReleaseSuffix(release)
	kernelVersion, err := semver.Make(release)
	if err != nil {
		log.Fatalf("Failed to parse kernel version(%s): %v\n", release, err)
	}

	switch {
	case kernelVersion.GTE(semver.MustParse("5.16.0")):
		kp, err := link.Kprobe("ipt_do_table", coll.Programs[progNameKprobeIptDoTable], nil)
		if err != nil {
			log.Fatalf("Opening kprobe ipt_do_table: %v\n", err)
		}
		t.links = append(t.links, kp)

	default:
		kp, err := link.Kprobe("ipt_do_table", coll.Programs[progNameKprobeIptDoTableOld], nil)
		if err != nil {
			log.Fatalf("Opening kprobe ipt_do_table: %v\n", err)
		}
		t.links = append(t.links, kp)
	}

	krp, err := link.Kretprobe("ipt_do_table", coll.Programs[progNameKretprobeIptDoTable], nil)
	if err != nil {
		log.Fatalf("Opening kretprobe ipt_do_table: %v\n", err)
	}
	t.links = append(t.links, krp)

	kp, err := link.Kprobe("nf_hook_slow", coll.Programs[progNameKprobeNfHookSlow], nil)
	if err != nil {
		log.Fatalf("Opening kprobe nf_hook_slow: %v\n", err)
	}
	t.links = append(t.links, kp)

	krp, err = link.Kretprobe("nf_hook_slow", coll.Programs[progNameKretprobeNfHook], nil)
	if err != nil {
		log.Fatalf("Opening kretprobe nf_hook_slow: %v\n", err)
	}
	t.links = append(t.links, krp)

	log.Printf("Attached iptables kprobes\n")

	return &t
}
