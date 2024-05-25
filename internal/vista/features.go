// SPDX-License-Identifier: Apache-2.0
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */
/* Copyright Leon Hwang */

package vista

import (
	"github.com/Asphaltt/vista/internal/build"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

// Very hacky way to check whether multi-link kprobe is supported.
func HaveBPFLinkKprobeMulti() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "probe_kpm_link",
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: ebpf.AttachTraceKprobeMulti,
		License:    "MIT",
	})
	if err != nil {
		return false
	}
	defer prog.Close()

	opts := link.KprobeMultiOptions{Symbols: []string{"vprintk"}}
	link, err := link.KretprobeMulti(prog, opts)
	if err != nil {
		return false
	}
	defer link.Close()

	return true
}

// Very hacky way to check whether tracing link is supported.
func HaveBPFLinkTracing() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "fexit_skb_clone",
		Type: ebpf.Tracing,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: ebpf.AttachTraceFExit,
		AttachTo:   "skb_clone",
		License:    "MIT",
	})
	if err != nil {
		return false
	}
	defer prog.Close()

	link, err := link.AttachTracing(link.TracingOptions{
		Program: prog,
	})
	if err != nil {
		return false
	}
	defer link.Close()

	return true
}

func HaveBpfSkbOutput() bool {
	spec, err := build.LoadVistaFeatures()
	if err != nil {
		return false
	}

	dummyName := "vista_dummy_tc"
	dummySpec := spec.Copy()
	dummySpec.Programs = map[string]*ebpf.ProgramSpec{
		dummyName: spec.Programs[dummyName],
	}

	coll, err := ebpf.NewCollection(dummySpec)
	if err != nil {
		return false
	}
	defer coll.Close()

	progName := "detect_bpf_skb_out"
	spec.Programs = map[string]*ebpf.ProgramSpec{
		progName: spec.Programs[progName],
	}

	spec.Programs[progName].AttachTarget = coll.Programs[dummyName]

	coll2, err := ebpf.NewCollection(spec)
	if err != nil {
		return false
	}
	defer coll2.Close()

	return true
}

func HaveBpfXdpOutput() bool {
	spec, err := build.LoadVistaFeatures()
	if err != nil {
		return false
	}

	dummyName := "vista_dummy_xdp"
	dummySpec := spec.Copy()
	dummySpec.Programs = map[string]*ebpf.ProgramSpec{
		dummyName: spec.Programs[dummyName],
	}

	coll, err := ebpf.NewCollection(dummySpec)
	if err != nil {
		return false
	}
	defer coll.Close()

	progName := "detect_bpf_xdp_out"
	spec.Programs = map[string]*ebpf.ProgramSpec{
		progName: spec.Programs[progName],
	}

	spec.Programs[progName].AttachTarget = coll.Programs[dummyName]

	coll2, err := ebpf.NewCollection(spec)
	if err != nil {
		return false
	}
	defer coll2.Close()

	return true
}

func HaveAvailableFilterFunctions() bool {
	_, err := getAvailableFilterFunctions()
	return err == nil
}
