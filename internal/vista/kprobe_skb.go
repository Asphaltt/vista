// SPDX-License-Identifier: Apache-2.0
/* Copyright 2024 Authors of Cilium */
/* Copyright Leon Hwang */

package vista

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/cheggaaa/pb/v3"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

const (
	progNameKprobeSkb1           = "kprobe_skb_1"
	progNameKprobeSkb2           = "kprobe_skb_2"
	progNameKprobeSkb3           = "kprobe_skb_3"
	progNameKprobeSkb4           = "kprobe_skb_4"
	progNameKprobeSkb5           = "kprobe_skb_5"
	progNameKprobeKfreeSkbReason = "kprobe_kfree_skb_reason"
	progNameKprobeKfreeSkb       = "kprobe_kfree_skb"
)

type skbKprober struct {
	links []link.Link

	kprobeMulti bool
	kprobeBatch uint
}

func (k *skbKprober) HaveLinks() bool {
	return len(k.links) > 0
}

func KprobeSkb(ctx context.Context, funcs Funcs, coll *ebpf.Collection, a2n Addr2Name, useKprobeMulti bool, batch uint, supportKfreeSkbReason bool, dropstack bool) *skbKprober {
	msg := "kprobe"
	if useKprobeMulti {
		msg = "kprobe-multi"
	}
	log.Printf("Attaching skb kprobes (via %s)...\n", msg)

	ignored := 0
	bar := pb.StartNew(len(funcs))

	runWithKfreeSkbReason := supportKfreeSkbReason
	if _, ok := funcs["kfree_skb_reason"]; ok {
		delete(funcs, "kfree_skb_reason")
	} else {
		runWithKfreeSkbReason = false
	}

	runWithKfreeSkb := dropstack
	if runWithKfreeSkb {
		delete(funcs, "__kfree_skb")
	}

	kprobes := make([]Kprobe, 0, len(funcs))
	funcsByPos := GetFuncsByPos(funcs)
	for pos, fns := range funcsByPos {
		fn, ok := coll.Programs[fmt.Sprintf("kprobe_skb_%d", pos)]
		if ok {
			kprobes = append(kprobes, Kprobe{HookFuncs: fns, Prog: fn})
		} else {
			ignored += len(fns)
			bar.Add(len(fns))
		}
	}

	var k skbKprober
	k.kprobeMulti = useKprobeMulti
	k.kprobeBatch = batch

	if runWithKfreeSkbReason {
		kp, err := link.Kprobe("kfree_skb_reason", coll.Programs[progNameKprobeKfreeSkbReason], nil)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.EADDRNOTAVAIL) {
				log.Fatalf("Opening kprobe kfree_skb_reason: %s\n", err)
			}
		} else {
			k.links = append(k.links, kp)
		}
	}

	if runWithKfreeSkb {
		kp, err := link.Kprobe("__kfree_skb", coll.Programs[progNameKprobeKfreeSkb], nil)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.EADDRNOTAVAIL) {
				log.Fatalf("Opening kprobe kfree_skb: %s\n", err)
			}
		} else {
			k.links = append(k.links, kp)
		}
	}

	if !useKprobeMulti {
		l, i := AttachKprobes(ctx, bar, kprobes, batch)
		k.links = append(k.links, l...)
		ignored += i
	} else {
		l, i := AttachKprobeMulti(ctx, bar, kprobes, a2n)
		k.links = append(k.links, l...)
		ignored += i
	}
	bar.Finish()
	select {
	case <-ctx.Done():
		k.DetachKprobes()
		os.Exit(0)
	default:
	}
	log.Printf("Attached skb kprobes (ignored %d)\n", ignored)

	return &k
}

func DetectKfreeSkbReason(spec *btf.Spec) bool {
	typ, err := spec.AnyTypeByName("kfree_skb_reason")
	if err != nil {
		if errors.Is(err, btf.ErrNotFound) {
			return false
		}

		log.Fatalf("Failed to find kfree_skb_reason: %v\n", err)
	}

	_, ok := typ.(*btf.Func)
	return ok
}

// DetachKprobes detaches kprobes concurrently.
func (k *skbKprober) DetachKprobes() {
	detachKprobes("skb", k.links, k.kprobeMulti, k.kprobeBatch)
}
