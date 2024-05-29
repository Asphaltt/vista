// SPDX-License-Identifier: Apache-2.0
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */
/* Copyright Leon Hwang */

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/Asphaltt/vista/internal/build"
	"github.com/Asphaltt/vista/internal/vista"
)

func main() {
	flags := vista.Flags{}
	flags.SetFlags()
	flags.Parse()

	if flags.ShowHelp {
		flags.PrintHelp()
		os.Exit(0)
	}
	if flags.ShowVersion {
		fmt.Printf("vista %s\n", vista.Version)
		os.Exit(0)
	}

	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{
		Cur: 8192,
		Max: 8192,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %s", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to set temporary rlimit: %s", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var btfSpec *btf.Spec
	var err error
	if flags.KernelBTF != "" {
		btfSpec, err = btf.LoadSpec(flags.KernelBTF)
	} else {
		btfSpec, err = btf.LoadKernelSpec()
	}
	if err != nil {
		log.Fatalf("Failed to load BTF spec: %s", err)
	}

	if flags.AllKMods {
		files, err := os.ReadDir("/sys/kernel/btf")
		if err != nil {
			log.Fatalf("Failed to read directory: %s", err)
		}

		flags.KMods = nil
		for _, file := range files {
			if !file.IsDir() && file.Name() != "vmlinux" {
				flags.KMods = append(flags.KMods, file.Name())
			}
		}
	}

	var useKprobeMulti bool
	if flags.KprobeBackend != "" && (flags.KprobeBackend != vista.BackendKprobe && flags.KprobeBackend != vista.BackendKprobeMulti) {
		log.Fatalf("Invalid tracing backend %s", flags.KprobeBackend)
	}
	// Until https://lore.kernel.org/bpf/20221025134148.3300700-1-jolsa@kernel.org/
	// has been backported to the stable, kprobe-multi cannot be used when attaching
	// to kmods.
	if flags.KprobeBackend == "" && len(flags.KMods) == 0 {
		useKprobeMulti = vista.HaveBPFLinkKprobeMulti() && vista.HaveAvailableFilterFunctions()
	} else if flags.KprobeBackend == vista.BackendKprobeMulti {
		useKprobeMulti = true
	}

	funcsSkb := vista.Funcs{}
	if flags.FilterTraceSkb {
		funcsSkb, err = vista.GetSkbFuncs(flags.FilterSkbFunc, btfSpec, flags.KMods, useKprobeMulti)
		if err != nil {
			log.Fatalf("Failed to get skb-accepting functions: %s", err)
		}
		if len(funcsSkb) == 0 {
			log.Fatalf("Cannot find a matching kernel skb-accepting function")
		}
	}

	funcsSk := vista.Funcs{}
	if flags.FilterTraceSk {
		funcsSk, err = vista.GetSkFuncs(flags.FilterSkFunc, btfSpec, flags.KMods, useKprobeMulti)
		if err != nil {
			log.Fatalf("Failed to get sk-accepting functions: %s", err)
		}
		if len(funcsSk) == 0 {
			log.Fatalf("Cannot find a matching kernel sk-accepting function")
		}
	}

	// If --filter-trace-tc/--filter-trace-xdp, it's to retrieve and print bpf
	// prog's name.
	addr2name, name2addr, err := vista.ParseKallsyms(funcsSkb, funcsSk,
		flags.OutputStack || flags.FilterSkbDropStack || len(flags.KMods) != 0 ||
			flags.FilterTraceTc || flags.FilterTraceXdp)
	if err != nil {
		log.Fatalf("Failed to get function addrs: %s", err)
	}

	var bpfSpec *ebpf.CollectionSpec
	switch {
	case flags.OutputSkb && useKprobeMulti:
		bpfSpec, err = build.LoadKProbeMultiVista()
	case flags.OutputSkb:
		bpfSpec, err = build.LoadKProbeVista()
	case useKprobeMulti:
		bpfSpec, err = build.LoadKProbeMultiVistaWithoutOutputSKB()
	default:
		bpfSpec, err = build.LoadKProbeVistaWithoutOutputSKB()
	}
	if err != nil {
		log.Fatalf("Failed to load bpf spec: %v", err)
	}

	if flags.FilterPcap != "" {
		vista.InjectPcapFilter(bpfSpec, &flags)
	}

	bpfConfig, err := vista.GetConfig(&flags)
	if err != nil {
		log.Fatalf("Failed to get vista config: %v", err)
	}
	if err := bpfSpec.RewriteConstants(map[string]interface{}{
		"CFG": bpfConfig,
	}); err != nil {
		log.Fatalf("Failed to rewrite config: %v", err)
	}

	haveFexit := vista.HaveBPFLinkTracing()
	if (flags.FilterTraceTc || flags.FilterTraceXdp) && !haveFexit {
		log.Fatalf("Current kernel does not support fentry/fexit to run with --filter-trace-tc/--filter-trace-xdp")
	}

	// As we know, for every fentry tracing program, there is a corresponding
	// bpf prog spec with attaching target and attaching function. So, we can
	// just copy the spec and keep the fentry_tc/fexit_tc/fentry_xdp/fexit_xdp
	// program spec only in the copied spec.
	var bpfSpecFentryTc *ebpf.CollectionSpec
	if flags.FilterTraceTc {
		bpfSpecFentryTc = bpfSpec.Copy()
		bpfSpecFentryTc.Programs = map[string]*ebpf.ProgramSpec{
			vista.ProgNameFentryTC:     bpfSpecFentryTc.Programs[vista.ProgNameFentryTC],
			vista.ProgNameFexitTC:      bpfSpecFentryTc.Programs[vista.ProgNameFexitTC],
			vista.ProgNameFentryTCPcap: bpfSpecFentryTc.Programs[vista.ProgNameFentryTCPcap],
			vista.ProgNameFexitTCPcap:  bpfSpecFentryTc.Programs[vista.ProgNameFexitTCPcap],
		}
	}
	var bpfSpecFentryXdp *ebpf.CollectionSpec
	if flags.FilterTraceXdp {
		bpfSpecFentryXdp = bpfSpec.Copy()
		bpfSpecFentryXdp.Programs = map[string]*ebpf.ProgramSpec{
			vista.ProgNameFentryXDP:     bpfSpecFentryXdp.Programs[vista.ProgNameFentryXDP],
			vista.ProgNameFexitXDP:      bpfSpecFentryXdp.Programs[vista.ProgNameFexitXDP],
			vista.ProgNameFentryXDPPcap: bpfSpecFentryXdp.Programs[vista.ProgNameFentryXDPPcap],
			vista.ProgNameFexitXDPPcap:  bpfSpecFentryXdp.Programs[vista.ProgNameFexitXDPPcap],
		}
	}

	vista.TrimBpfSpec(bpfSpec, &flags, haveFexit)

	var opts ebpf.CollectionOptions
	opts.Programs.KernelTypes = btfSpec
	opts.Programs.LogLevel = ebpf.LogLevelInstruction
	opts.Programs.LogSize = ebpf.DefaultVerifierLogSize * 100

	coll, err := ebpf.NewCollectionWithOptions(bpfSpec, opts)
	if err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}

		log.Fatalf("Failed to load objects: %s\n%+v", verifierLog, err)
	}
	defer coll.Close()

	havePcapFile := flags.PcapFile != ""

	traceTc := false
	if flags.FilterTraceTc {
		if havePcapFile && !vista.HaveBpfSkbOutput() {
			log.Fatalf("Current kernel does not support skb output to run with --filter-trace-tc --pcap-file %s", flags.PcapFile)
		}
		t := vista.TraceTC(vista.TracingOptions{
			Coll:      coll,
			Spec:      bpfSpecFentryTc,
			Opts:      &opts,
			OutputSkb: flags.OutputSkb,
			Pcap:      havePcapFile,
			PcapModes: flags.PcapMode,
			N2A:       name2addr,
		})
		defer t.Close()
		traceTc = t.HaveTracing()
		if traceTc {
			log.Println("Tracing tc progs..")
		} else {
			log.Println("No tc-bpf progs found to trace!")
		}
	}

	traceXdp := false
	if flags.FilterTraceXdp {
		if havePcapFile && !vista.HaveBpfXdpOutput() {
			log.Fatalf("Current kernel does not support xdp output to run with --filter-trace-xdp --pcap-file %s", flags.PcapFile)
		}
		t := vista.TraceXDP(vista.TracingOptions{
			Coll:      coll,
			Spec:      bpfSpecFentryXdp,
			Opts:      &opts,
			OutputSkb: flags.OutputSkb,
			Pcap:      havePcapFile,
			PcapModes: flags.PcapMode,
			N2A:       name2addr,
		})
		defer t.Close()
		traceXdp = t.HaveTracing()
		if traceXdp {
			log.Println("Tracing xdp progs..")
		} else {
			log.Println("No xdp progs found to trace!")
		}
	}

	kprobeIptables := false
	if flags.FilterTraceIptables {
		k := vista.KprobeIptables(coll)
		defer k.Close()
		kprobeIptables = k.HaveLinks()
		delete(funcsSkb, "ipt_do_table")
		delete(funcsSkb, "nf_hook_slow")
	}

	kprobeTCP := false
	if flags.FilterTraceTCP {
		k := vista.KprobeTCP(coll)
		defer k.Close()
		kprobeTCP = k.HaveLinks()
	}

	kprobeSkb := false
	if (flags.FilterTraceSkb && len(funcsSkb) != 0) || flags.FilterSkbDropStack {
		k := vista.KprobeSkb(ctx, funcsSkb, coll, addr2name, useKprobeMulti,
			flags.FilterKprobeBatch, vista.DetectKfreeSkbReason(btfSpec),
			flags.FilterSkbDropStack)
		defer k.DetachKprobes()
		kprobeSkb = k.HaveLinks()
	}

	if flags.FilterTrackSkb && kprobeSkb {
		t := vista.TrackSkb(coll, haveFexit)
		defer t.Close()
	}

	kprobeSk := false
	if flags.FilterTraceSk && len(funcsSk) != 0 {
		k := vista.KprobeSock(ctx, funcsSk, coll, addr2name, useKprobeMulti,
			flags.FilterKprobeBatch)
		defer k.DetachKprobes()
		kprobeSk = k.HaveLinks()
	}

	if !traceTc && !traceXdp && !kprobeSkb && !kprobeSk && !kprobeIptables && !kprobeTCP {
		log.Fatalf("No kprobe/tc-bpf/xdp to trace!\nDo you miss --filter-trace-skb/--filter-trace-sk/--filter-skb-drop-stack/--filter-trace-iptables/--filter-trace-tcp/--filter-trace-tc/--filter-trace-xdp?")
	}

	log.Println("Listening for events..")

	if flags.ReadyFile != "" {
		file, err := os.Create(flags.ReadyFile)
		if err != nil {
			log.Fatalf("Failed to create ready file: %s", err)
		}
		file.Close()
	}

	printSkbMap := coll.Maps["print_skb_map"]
	printStackMap := coll.Maps["print_stack_map"]
	output, err := vista.NewOutput(&flags, printSkbMap, printStackMap, addr2name, useKprobeMulti, btfSpec)
	if err != nil {
		log.Fatalf("Failed to create outputer: %s", err)
	}
	defer output.Close()
	output.PrintHeader()

	defer func() {
		select {
		case <-ctx.Done():
			log.Println("Received signal, exiting program..")
		default:
			log.Printf("Printed %d events, exiting program..\n", flags.OutputLimitLines)
		}
	}()

	errg, ectx := errgroup.WithContext(ctx)

	counter := vista.NewOutputCounter(flags.OutputLimitLines)

	events := coll.Maps["events"]
	reader, err := perf.NewReaderWithOptions(events, int(flags.PerCPUBuffer), perf.ReaderOptions{
		Watermark: 1,
	})
	if err != nil {
		log.Fatalf("Failed to create perf reader: %s", err)
	}

	errg.Go(func() error {
		<-ectx.Done()
		_ = reader.Close()
		return nil
	})

	errg.Go(func() error {
		return loopEvents(ectx, reader, counter, output)
	})

	err = errg.Wait()
	if err != nil && !errors.Is(err, errFinished) {
		log.Fatalf("Failed to run vista: %v", err)
	}
}

var errFinished = errors.New("finished")

func loopEvents(ctx context.Context, reader *perf.Reader, counter *vista.OutputCounter, output *vista.Output) error {
	next := true
	for next {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return errFinished
			}

			return fmt.Errorf("failed to read perf record: %w", err)
		}

		if record.LostSamples > 0 {
			log.Printf("Lost %d samples of pcap events\n", record.LostSamples)
		}

		raw := record.RawSample
		event, err := vista.NewOutputEvent(raw)
		if err != nil {
			log.Printf("Failed to parse pcap event: %v\n", err)
			continue
		}

		if !event.IsPcap {
			output.Print(event)
		} else {
			output.Pcap(event)
		}

		next = counter.Next()
	}

	return errFinished
}
