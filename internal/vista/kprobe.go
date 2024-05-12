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
	"sync"
	"syscall"

	"github.com/cheggaaa/pb/v3"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sync/errgroup"
)

type Kprobe struct {
	hookFunc  string // internal use
	HookFuncs []string
	Prog      *ebpf.Program
}

func attachKprobes(ctx context.Context, bar *pb.ProgressBar, kprobes []Kprobe) (links []link.Link, ignored int, err error) {
	links = make([]link.Link, 0, len(kprobes))
	for _, kprobe := range kprobes {
		select {
		case <-ctx.Done():
			return

		default:
		}

		var kp link.Link
		kp, err = link.Kprobe(kprobe.hookFunc, kprobe.Prog, nil)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.EADDRNOTAVAIL) {
				err = fmt.Errorf("opening kprobe %s: %w", kprobe.hookFunc, err)
				return
			} else {
				err = nil
				ignored++
			}
		} else {
			links = append(links, kp)
		}

		bar.Increment()
	}

	return
}

// AttachKprobes attaches kprobes concurrently.
func AttachKprobes(ctx context.Context, bar *pb.ProgressBar, kps []Kprobe, batch uint) (links []link.Link, ignored int) {
	if batch == 0 {
		log.Fatal("--filter-kprobe-batch must be greater than 0")
	}

	var kprobes []Kprobe
	for _, kp := range kps {
		for _, fn := range kp.HookFuncs {
			kprobes = append(kprobes, Kprobe{
				hookFunc: fn,
				Prog:     kp.Prog,
			})
		}
	}

	if len(kprobes) == 0 {
		return
	}

	errg, ctx := errgroup.WithContext(ctx)

	var mu sync.Mutex
	links = make([]link.Link, 0, len(kprobes))

	attaching := func(kprobes []Kprobe) error {
		l, i, e := attachKprobes(ctx, bar, kprobes)
		if e != nil {
			return e
		}

		mu.Lock()
		links = append(links, l...)
		ignored += i
		mu.Unlock()

		return nil
	}

	var i uint
	for i = 0; i+batch < uint(len(kprobes)); i += batch {
		kps := kprobes[i : i+batch]
		errg.Go(func() error {
			return attaching(kps)
		})
	}
	if i < uint(len(kprobes)) {
		kps := kprobes[i:]
		errg.Go(func() error {
			return attaching(kps)
		})
	}

	if err := errg.Wait(); err != nil {
		log.Fatalf("Attaching kprobes: %v\n", err)
	}

	return
}

// AttachKprobeMulti attaches kprobe-multi serially.
func AttachKprobeMulti(ctx context.Context, bar *pb.ProgressBar, kprobes []Kprobe, a2n Addr2Name) (links []link.Link, ignored int) {
	links = make([]link.Link, 0, len(kprobes))

	for _, kp := range kprobes {
		select {
		case <-ctx.Done():
			return
		default:
		}

		addrs := make([]uintptr, 0, len(kp.HookFuncs))
		for _, fn := range kp.HookFuncs {
			if addr, ok := a2n.Name2AddrMap[fn]; ok {
				addrs = append(addrs, addr...)
			} else {
				ignored += 1
				bar.Increment()
				continue
			}
		}

		if len(addrs) == 0 {
			continue
		}

		opts := link.KprobeMultiOptions{Addresses: addrs}
		l, err := link.KprobeMulti(kp.Prog, opts)
		bar.Add(len(kp.HookFuncs))
		if err != nil {
			log.Fatalf("Opening kprobe-multi: %s\n", err)
		}

		links = append(links, l)
	}

	return
}

func detachKprobes(msg string, links []link.Link, kprobeMulti bool, batch uint) {
	log.Printf("Detaching %s kprobes...\n", msg)

	bar := pb.StartNew(len(links))
	defer bar.Finish()

	if kprobeMulti || batch >= uint(len(links)) {
		for _, l := range links {
			_ = l.Close()
			bar.Increment()
		}
		return
	}
	var errg errgroup.Group
	var i uint
	for i = 0; i+batch < uint(len(links)); i += batch {
		l := links[i : i+batch]
		errg.Go(func() error {
			for _, l := range l {
				_ = l.Close()
				bar.Increment()
			}
			return nil
		})
	}
	for ; i < uint(len(links)); i++ {
		_ = links[i].Close()
		bar.Increment()
	}
	_ = errg.Wait()
}
