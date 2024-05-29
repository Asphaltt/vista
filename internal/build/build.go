// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Leon Hwang.

package build

//go:generate sh -c "echo Generating for $TARGET_GOARCH"

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target $TARGET_GOARCH -cc clang -no-strip VistaFeatures ../../bpf/features.c -- -I../../bpf/headers -Wno-address-of-packed-member

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target $TARGET_GOARCH -cc clang -no-strip KProbeVista ../../bpf/vista.c -- -DOUTPUT_SKB -I../../bpf/headers -Wno-address-of-packed-member
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target $TARGET_GOARCH -cc clang -no-strip KProbeMultiVista ../../bpf/vista.c -- -DOUTPUT_SKB -DHAS_KPROBE_MULTI -I../../bpf/headers -Wno-address-of-packed-member
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target $TARGET_GOARCH -cc clang -no-strip KProbeVistaWithoutOutputSKB ../../bpf/vista.c -- -I../../bpf/headers -Wno-address-of-packed-member
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target $TARGET_GOARCH -cc clang -no-strip KProbeMultiVistaWithoutOutputSKB ../../bpf/vista.c -- -D HAS_KPROBE_MULTI -I../../bpf/headers -Wno-address-of-packed-member
