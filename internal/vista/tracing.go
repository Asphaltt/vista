// SPDX-License-Identifier: Apache-2.0
/* Copyright 2024 Authors of Cilium */
/* Copyright Leon Hwang */

package vista

import (
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sync/errgroup"
)

const (
	ProgNameFentryTC = "fentry_tc"
	ProgNameFexitTC  = "fexit_tc"

	ProgNameFentryTCPcap = "fentry_tc_pcap"
	ProgNameFexitTCPcap  = "fexit_tc_pcap"

	ProgNameFentryXDP = "fentry_xdp"
	ProgNameFexitXDP  = "fexit_xdp"

	ProgNameFentryXDPPcap = "fentry_xdp_pcap"
	ProgNameFexitXDPPcap  = "fexit_xdp_pcap"

	pcapModeEntry = "entry"
	pcapModeExit  = "exit"
)

type tracing struct {
	sync.Mutex
	links []link.Link
}

func (t *tracing) HaveTracing() bool {
	t.Lock()
	defer t.Unlock()

	return len(t.links) > 0
}

func (t *tracing) Close() {
	t.Lock()
	defer t.Unlock()

	t.detach()
}

func (t *tracing) detach() {
	var errg errgroup.Group

	for _, l := range t.links {
		l := l
		errg.Go(func() error {
			_ = l.Close()
			return nil
		})
	}

	_ = errg.Wait()
}

func (t *tracing) addLink(l link.Link) {
	t.Lock()
	defer t.Unlock()

	t.links = append(t.links, l)
}

type TracingOptions struct {
	Coll *ebpf.Collection
	Spec *ebpf.CollectionSpec
	Opts *ebpf.CollectionOptions

	OutputSkb bool
	Pcap      bool
	PcapModes []string
	N2A       BpfProgName2Addr

	progType ebpf.ProgramType
}

func (t *tracing) traceProg(options *TracingOptions, prog *ebpf.Program, fentryName, fexitName string) error {
	entryFn, name, err := getEntryFuncName(prog)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return nil
		}
		return fmt.Errorf("failed to get entry function name: %w", err)
	}

	// Skip those dummy progs used for feature detection.
	if strings.HasPrefix(entryFn, "vista_dummy_") {
		return nil
	}

	// The addr may hold the wrong rip value, because two addresses could
	// have one same symbol. As discussed before, that doesn't affect the
	// symbol resolution because even a "wrong" rip can be matched to the
	// right symbol. However, this could make a difference when we want to
	// distinguish which exact bpf prog is called.
	//   -- @jschwinger233

	addr, ok := options.N2A[entryFn]
	if !ok {
		addr, ok = options.N2A[name]
		if !ok {
			return fmt.Errorf("failed to find address for function %s of bpf prog %v", name, prog)
		}
	}

	spec := options.Spec.Copy()
	if err := spec.RewriteConstants(map[string]any{
		"BPF_PROG_ADDR": addr,
	}); err != nil {
		return fmt.Errorf("failed to rewrite bpf prog addr: %w", err)
	}

	spec.Programs[fentryName].AttachTarget = prog
	spec.Programs[fentryName].AttachTo = entryFn
	spec.Programs[fexitName].AttachTarget = prog
	spec.Programs[fexitName].AttachTo = entryFn
	coll, err := ebpf.NewCollectionWithOptions(spec, *options.Opts)
	if err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}

		return fmt.Errorf("failed to load objects: %s\n%w", verifierLog, err)
	}
	defer coll.Close()

	if !options.Pcap || slices.Contains(options.PcapModes, pcapModeEntry) {
		tracing, err := link.AttachTracing(link.TracingOptions{
			Program:    coll.Programs[fentryName],
			AttachType: ebpf.AttachTraceFEntry,
		})
		if err != nil {
			return fmt.Errorf("failed to attach tracing: %w", err)
		}

		t.addLink(tracing)
	}

	if options.Pcap && slices.Contains(options.PcapModes, pcapModeExit) {
		tracing, err := link.AttachTracing(link.TracingOptions{
			Program:    coll.Programs[fexitName],
			AttachType: ebpf.AttachTraceFExit,
		})
		if err != nil {
			return fmt.Errorf("failed to attach tracing: %w", err)
		}

		t.addLink(tracing)
	}

	return nil
}

func (t *tracing) trace(options *TracingOptions, fentryName, fexitName, fentryPcap, fexitPcap string) error {
	progs, err := listBpfProgs(options.progType)
	if err != nil {
		log.Fatalf("failed to list bpf progs: %v", err)
	}
	defer func() {
		for _, p := range progs {
			_ = p.Close()
		}
	}()

	entry, exit := fentryName, fexitName
	if options.Pcap {
		delete(options.Spec.Programs, fentryName)
		delete(options.Spec.Programs, fexitName)

		entry, exit = fentryPcap, fexitPcap
	} else {
		delete(options.Spec.Programs, fentryPcap)
		delete(options.Spec.Programs, fexitPcap)
	}

	// Reusing maps from previous collection is to handle the events together
	// with the kprobes.
	replacedMaps := map[string]*ebpf.Map{
		"events":          options.Coll.Maps["events"],
		"print_stack_map": options.Coll.Maps["print_stack_map"],
	}
	if options.OutputSkb {
		replacedMaps["print_skb_map"] = options.Coll.Maps["print_skb_map"]
	}
	options.Opts.MapReplacements = replacedMaps

	t.links = make([]link.Link, 0, len(progs)*2)

	var errg errgroup.Group

	for _, prog := range progs {
		prog := prog
		errg.Go(func() error {
			return t.traceProg(options, prog, entry, exit)
		})
	}

	if err := errg.Wait(); err != nil {
		t.Close()
		return fmt.Errorf("failed to trace bpf progs: %w", err)
	}

	return nil
}

func TraceTC(options TracingOptions) *tracing {
	var t tracing
	options.progType = ebpf.SchedCLS
	if err := t.trace(&options, ProgNameFentryTC, ProgNameFexitTC, ProgNameFentryTCPcap, ProgNameFexitTCPcap); err != nil {
		log.Fatalf("failed to trace TC progs: %v", err)
	}

	return &t
}

func TraceXDP(options TracingOptions) *tracing {
	var t tracing
	options.progType = ebpf.XDP
	if err := t.trace(&options, ProgNameFentryXDP, ProgNameFexitXDP, ProgNameFentryXDPPcap, ProgNameFexitXDPPcap); err != nil {
		log.Fatalf("failed to trace XDP progs: %v", err)
	}

	return &t
}
