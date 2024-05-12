// SPDX-License-Identifier: Apache-2.0
/* Copyright 2024 Authors of Cilium */
/* Copyright Leon Hwang */

package vista

import (
	"errors"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type skbTracker struct {
	links []link.Link
}

func (t *skbTracker) Close() {
	for _, l := range t.links {
		_ = l.Close()
	}
	t.links = nil
}

func TrackSkb(coll *ebpf.Collection, haveFexit bool) *skbTracker {
	var t skbTracker

	kp, err := link.Kprobe("kfree_skbmem", coll.Programs["kprobe_skb_lifetime_termination"], nil)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Fatalf("Opening kprobe kfree_skbmem: %s\n", err)
		} else {
			log.Printf("Warn: kfree_skbmem not found, vista is likely to mismatch skb due to lack of skb lifetime management\n")
		}
	} else {
		t.links = append(t.links, kp)
	}

	if haveFexit {
		progs := []*ebpf.Program{
			coll.Programs["fexit_skb_clone"],
			coll.Programs["fexit_skb_copy"],
		}
		for _, prog := range progs {
			fexit, err := link.AttachTracing(link.TracingOptions{
				Program: prog,
			})
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					log.Fatalf("Opening tracing(%s): %s\n", prog, err)
				}
			} else {
				t.links = append(t.links, fexit)
			}
		}
	}

	return &t
}
