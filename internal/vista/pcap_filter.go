// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package vista

import (
	"log"

	"github.com/Asphaltt/vista/internal/libpcap"
	"github.com/cilium/ebpf"
)

func injectPcapFilter(spec *ebpf.CollectionSpec, progNames []string, f *Flags) {
	for _, progName := range progNames {
		progSpec, ok := spec.Programs[progName]
		if !ok {
			log.Fatalf("Failed to find program %s to inject pcap-filter", progName)
		}

		if err := libpcap.InjectFilters(progSpec, f.FilterPcap); err != nil {
			log.Fatalf("Failed to inject filter ebpf for %s: %v", progName, err)
		}
	}
}

func InjectPcapFilter(spec *ebpf.CollectionSpec, f *Flags) {
	if f.FilterPcap == "" {
		return
	}

	if f.FilterTraceSkb {
		progNames := []string{
			progNameKprobeSkb1,
			progNameKprobeSkb2,
			progNameKprobeSkb3,
			progNameKprobeSkb4,
			progNameKprobeSkb5,
			progNameKprobeKfreeSkbReason,
			progNameKprobeKfreeSkb,
		}
		injectPcapFilter(spec, progNames, f)
	} else if f.FilterSkbDropStack {
		injectPcapFilter(spec, []string{progNameKprobeKfreeSkb}, f)
	}

	if f.FilterTraceTc {
		injectPcapFilter(spec, []string{
			ProgNameFentryTC,
			ProgNameFexitTC,
			ProgNameFentryTCPcap,
			ProgNameFexitTCPcap,
		}, f)
	}

	if f.FilterTraceXdp {
		progNames := []string{
			ProgNameFentryXDP,
			ProgNameFexitXDP,
			ProgNameFentryXDPPcap,
			ProgNameFexitXDPPcap,
		}
		for _, progName := range progNames {
			progSpec := spec.Programs[progName]
			if err := libpcap.InjectL2Filter(progSpec, f.FilterPcap); err != nil {
				log.Fatalf("Failed to inject filter ebpf for %s: %v", progName, err)
			}
		}
	}

	if f.FilterTraceIptables {
		injectPcapFilter(spec, []string{
			progNameKprobeIptDoTable,
			progNameKprobeIptDoTableOld,
			progNameKprobeNfHookSlow,
		}, f)
	}
}
