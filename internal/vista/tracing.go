// SPDX-License-Identifier: Apache-2.0
/* Copyright 2024 Authors of Cilium */
/* Copyright Leon Hwang */

package vista

import (
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sync/errgroup"
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

func (t *tracing) traceProg(spec *ebpf.CollectionSpec,
	opts *ebpf.CollectionOptions, prog *ebpf.Program, n2a BpfProgName2Addr,
	fentryName, fexitName string,
) error {
	entryFn, name, err := getEntryFuncName(prog)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return nil
		}
		return fmt.Errorf("failed to get entry function name: %w", err)
	}

	// The addr may hold the wrong rip value, because two addresses could
	// have one same symbol. As discussed before, that doesn't affect the
	// symbol resolution because even a "wrong" rip can be matched to the
	// right symbol. However, this could make a difference when we want to
	// distinguish which exact bpf prog is called.
	//   -- @jschwinger233

	addr, ok := n2a[entryFn]
	if !ok {
		addr, ok = n2a[name]
		if !ok {
			return fmt.Errorf("failed to find address for function %s of bpf prog %v", name, prog)
		}
	}

	spec = spec.Copy()
	if err := spec.RewriteConstants(map[string]any{
		"BPF_PROG_ADDR": addr,
	}); err != nil {
		return fmt.Errorf("failed to rewrite bpf prog addr: %w", err)
	}

	spec.Programs[fentryName].AttachTarget = prog
	spec.Programs[fentryName].AttachTo = entryFn
	spec.Programs[fexitName].AttachTarget = prog
	spec.Programs[fexitName].AttachTo = entryFn
	coll, err := ebpf.NewCollectionWithOptions(spec, *opts)
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

	tracing, err := link.AttachTracing(link.TracingOptions{
		Program: coll.Programs[fentryName],
	})
	if err != nil {
		return fmt.Errorf("failed to attach tracing: %w", err)
	}

	t.addLink(tracing)

	tracing, err = link.AttachTracing(link.TracingOptions{
		Program: coll.Programs[fexitName],
	})
	if err != nil {
		return fmt.Errorf("failed to attach tracing: %w", err)
	}

	t.addLink(tracing)

	return nil
}

func (t *tracing) trace(coll *ebpf.Collection, spec *ebpf.CollectionSpec,
	opts *ebpf.CollectionOptions, outputSkb, pcap bool, n2a BpfProgName2Addr,
	progType ebpf.ProgramType, fentryName, fexitName string,
) error {
	progs, err := listBpfProgs(progType)
	if err != nil {
		log.Fatalf("failed to list bpf progs: %w", err)
	}
	defer func() {
		for _, p := range progs {
			_ = p.Close()
		}
	}()

	// Reusing maps from previous collection is to handle the events together
	// with the kprobes.
	replacedMaps := map[string]*ebpf.Map{
		"events":          coll.Maps["events"],
		"print_stack_map": coll.Maps["print_stack_map"],
	}
	if outputSkb {
		replacedMaps["print_skb_map"] = coll.Maps["print_skb_map"]
	}
	if pcap {
		replacedMaps["pcap_events"] = coll.Maps["pcap_events"]
	}
	opts.MapReplacements = replacedMaps

	t.links = make([]link.Link, 0, len(progs)*2)

	var errg errgroup.Group

	for _, prog := range progs {
		prog := prog
		errg.Go(func() error {
			return t.traceProg(spec, opts, prog, n2a, fentryName, fexitName)
		})
	}

	if err := errg.Wait(); err != nil {
		t.Close()
		return fmt.Errorf("failed to trace bpf progs: %w", err)
	}

	return nil
}

func TraceTC(coll *ebpf.Collection, spec *ebpf.CollectionSpec,
	opts *ebpf.CollectionOptions, outputSkb, pcap bool, n2a BpfProgName2Addr,
) *tracing {
	var t tracing
	if err := t.trace(coll, spec, opts, outputSkb, pcap, n2a, ebpf.SchedCLS, "fentry_tc", "fexit_tc"); err != nil {
		log.Fatalf("failed to trace TC progs: %v", err)
	}

	return &t
}

func TraceXDP(coll *ebpf.Collection, spec *ebpf.CollectionSpec,
	opts *ebpf.CollectionOptions, outputSkb, pcap bool, n2a BpfProgName2Addr,
) *tracing {
	var t tracing
	if err := t.trace(coll, spec, opts, outputSkb, pcap, n2a, ebpf.XDP, "fentry_xdp", "fexit_xdp"); err != nil {
		log.Fatalf("failed to trace XDP progs: %v", err)
	}

	return &t
}
