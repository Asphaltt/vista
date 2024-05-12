// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package vista

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/cheggaaa/pb/v3"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type sockKprober struct {
	links []link.Link

	kprobeMulti bool
	kprobeBatch uint
}

func (k *sockKprober) HaveLinks() bool {
	return len(k.links) > 0
}

func KprobeSock(ctx context.Context, funcs Funcs, coll *ebpf.Collection,
	a2n Addr2Name, useKprobeMulti bool, batch uint,
) *sockKprober {
	msg := "kprobe"
	if useKprobeMulti {
		msg = "kprobe-multi"
	}
	log.Printf("Attaching sk kprobes (via %s)...\n", msg)

	ignored := 0
	bar := pb.StartNew(len(funcs))

	kprobes := make([]Kprobe, 0, len(funcs))
	funcsByPos := GetFuncsByPos(funcs)
	for pos, fns := range funcsByPos {
		fn, ok := coll.Programs[fmt.Sprintf("kprobe_sk_%d", pos)]
		if ok {
			kprobes = append(kprobes, Kprobe{HookFuncs: fns, Prog: fn})
		} else {
			ignored += len(fns)
			bar.Add(len(fns))
		}
	}

	var k sockKprober
	k.kprobeMulti = useKprobeMulti
	k.kprobeBatch = batch

	if !useKprobeMulti {
		l, i := AttachKprobes(ctx, bar, kprobes, batch)
		k.links = l
		ignored += i
	} else {
		l, i := AttachKprobeMulti(ctx, bar, kprobes, a2n)
		k.links = l
		ignored += i
	}
	bar.Finish()
	select {
	case <-ctx.Done():
		k.DetachKprobes()
		os.Exit(0)
	default:
	}

	log.Printf("Attached sk kprobes (ignored %d)\n", ignored)

	return &k
}

func (k *sockKprober) DetachKprobes() {
	detachKprobes("sk", k.links, k.kprobeMulti, k.kprobeBatch)
}
