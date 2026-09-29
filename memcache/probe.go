// Package memcache provides a OTel eBPF profiler extension probe to profile
// memory cache hits and misses.
package memcache

import (
	"context"
	"fmt"
	"unsafe"

	cebpf "github.com/cilium/ebpf"
	"github.com/elastic/go-perf"

	"go.opentelemetry.io/collector/component"

	"go.opentelemetry.io/ebpf-profiler/collector"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// Compile time check to make sure implementations satisfy the interfaces.
var (
	_ collector.ProbeExtension = (*memcacheProbe)(nil)
	_ tracer.Probe             = (*memcacheProbe)(nil)
)

type Config struct{}

// Validate implements confmap.Validator.
func (c *Config) Validate() error {
	return nil
}

type memcacheProbe struct {
	coll   *cebpf.Collection
	ref    *tracer.CollectTrampolineRef
	events []*perf.Event
}

func (mc *memcacheProbe) Probe() tracer.Probe {
	return &memcacheProbe{}
}

func (mc *memcacheProbe) Start(_ context.Context, _ component.Host) error {
	return nil
}

func (mc *memcacheProbe) Shutdown(_ context.Context) error {
	return nil
}

func (mc *memcacheProbe) Load(ctx context.Context, reg tracer.ProbeRegistrar, probeCtx *tracer.ProbeContext) error {
	ref, err := probeCtx.RegisterCollectTrampoline(&samples.TypeMetadata{
		SampleTypes:  []samples.SampleType{{Type: "events", Unit: "count"}},
		ReportValues: true,
		AppendValues: samples.AppendFirstContextValue,
	}, tracer.ProbePerfEvent)
	if err != nil {
		return err
	}

	spec, err := loadMemcache()
	if err != nil {
		ref.Close()
		return err
	}

	tailCallMap, err := cebpf.NewMap(spec.Maps[memcacheMapMemcacheTrampoline])
	if err != nil {
		ref.Close()
		return err
	}

	if err := ref.InsertInto(tailCallMap, 0); err != nil {
		tailCallMap.Close()
		ref.Close()
		return err
	}

	coll, err := cebpf.NewCollectionWithOptions(spec, cebpf.CollectionOptions{
		MapReplacements: map[string]*cebpf.Map{
			memcacheMapMemcacheValue:      ref.CtxMap,
			memcacheMapMemcacheTrampoline: tailCallMap,
		},
	})
	if err != nil {
		tailCallMap.Close()
		ref.Close()
		return err
	}
	mc.coll = coll
	mc.ref = ref

	cpus, err := getOnlineCPUIDs()
	if err != nil {
		return err
	}

	attr := &perf.Attr{
		Type:   perf.HardwareCacheEvent,
		Config: makeCacheConfig(PerfHWCacheL1D, PerfHWCacheOpRead, PerfHWCacheResultMiss),
		Sample: 4096 << 8,
		Options: perf.Options{
			Disabled:      true,
			ExcludeKernel: true,
		},
	}

	eventsMap := coll.Maps[memcacheMapL1dReadMiss]
	prog := coll.Programs[memcacheProgReadPerfEventHook]
	progFD := uint32(prog.FD())

	for _, cpu := range cpus {
		perfEvent, err := perf.Open(attr, perf.AllThreads, cpu, nil)
		if err != nil {
			return fmt.Errorf("failed to open perf event on CPU %d: %v", cpu, err)
		}

		if err := perfEvent.SetBPF(progFD); err != nil {
			return fmt.Errorf("failed to attach eBPF program to perf event: %v", err)
		}

		eventFD, err := perfEvent.FD()
		if err != nil {
			return fmt.Errorf("getting FD failed: %v", err)
		}

		if err := eventsMap.Update(unsafe.Pointer(&cpu), unsafe.Pointer(&eventFD), cebpf.UpdateAny); err != nil {
			return fmt.Errorf("map update failed: %v", err)
		}

		if err := perfEvent.Enable(); err != nil {
			return fmt.Errorf("failed to enable perf event on CPU %d: %v", cpu, err)
		}

		mc.events = append(mc.events, perfEvent)
	}

	return nil
}

func (mc *memcacheProbe) Unload() error {
	for _, ev := range mc.events {
		ev.Disable()
		ev.Close()
	}

	if mc.coll != nil {
		mc.coll.Close()
	}
	if mc.ref != nil {
		return mc.ref.Close()
	}

	return nil
}
