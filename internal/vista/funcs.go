// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package vista

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"

	"github.com/cilium/ebpf/btf"
)

type Funcs map[string]int

// getAvailableFilterFunctions return list of functions to which it is possible
// to attach kprobes.
func getAvailableFilterFunctions() (map[string]struct{}, error) {
	availableFuncs := make(map[string]struct{})
	f, err := os.Open("/sys/kernel/debug/tracing/available_filter_functions")
	if err != nil {
		return nil, fmt.Errorf("failed to open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		availableFuncs[scanner.Text()] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return availableFuncs, nil
}

func getFuncs(pattern, structName string, spec *btf.Spec, kmods []string, kprobeMulti bool) (Funcs, error) {
	funcs := Funcs{}

	type iterator struct {
		kmod string
		iter *btf.TypesIterator
	}

	reg, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regular expression %v", err)
	}

	var availableFuncs map[string]struct{}
	if kprobeMulti {
		availableFuncs, err = getAvailableFilterFunctions()
		if err != nil {
			log.Printf("Failed to retrieve available ftrace functions (is /sys/kernel/debug/tracing mounted?): %s", err)
		}
	}

	iters := []iterator{{"", spec.Iterate()}}
	for _, module := range kmods {
		path := filepath.Join("/sys/kernel/btf", module)
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open %s: %v", path, err)
		}
		defer f.Close()

		modSpec, err := btf.LoadSplitSpecFromReader(f, spec)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s btf: %v", module, err)
		}
		iters = append(iters, iterator{module, modSpec.Iterate()})
	}

	for _, it := range iters {
		for it.iter.Next() {
			typ := it.iter.Type
			fn, ok := typ.(*btf.Func)
			if !ok {
				continue
			}

			fnName := string(fn.Name)

			if pattern != "" && reg.FindString(fnName) != fnName {
				continue
			}

			if kprobeMulti {
				availableFnName := fnName
				if it.kmod != "" {
					availableFnName = fmt.Sprintf("%s [%s]", fnName, it.kmod)
				}
				if _, ok := availableFuncs[availableFnName]; !ok {
					continue
				}
			}

			fnProto := fn.Type.(*btf.FuncProto)
			i := 1
			for _, p := range fnProto.Params {
				if ptr, ok := p.Type.(*btf.Pointer); ok {
					if strct, ok := ptr.Target.(*btf.Struct); ok {
						if strct.Name == structName && i <= 5 {
							name := fnName
							if kprobeMulti && it.kmod != "" {
								name = fmt.Sprintf("%s [%s]", fnName, it.kmod)
							}
							funcs[name] = i
							continue
						}
					}
				}
				i += 1
			}
		}
	}

	return funcs, nil
}

func GetSkbFuncs(pattern string, spec *btf.Spec, kmods []string, kprobeMulti bool) (Funcs, error) {
	return getFuncs(pattern, "sk_buff", spec, kmods, kprobeMulti)
}

func GetSkFuncs(pattern string, spec *btf.Spec, kmods []string, kprobeMulti bool) (Funcs, error) {
	return getFuncs(pattern, "sock", spec, kmods, kprobeMulti)
}

func GetFuncsByPos(funcs Funcs) map[int][]string {
	ret := make(map[int][]string, len(funcs))
	for fn, pos := range funcs {
		ret[pos] = append(ret[pos], fn)
	}
	return ret
}
