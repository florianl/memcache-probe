// Package memcache provides a OTel eBPF profiler extension probe to profile
// memory cache hits and misses.
package memcache

import (
	"context"
	"errors"
	"fmt"

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

type eventProbe struct {
	coll   *cebpf.Collection
	ref    *tracer.CollectTrampolineRef
	events []*perf.Event
}

type memcacheProbe struct {
	cfg    *Config
	probes []*eventProbe
}

func (mc *memcacheProbe) Probe() tracer.Probe {
	return &memcacheProbe{cfg: mc.cfg}
}

func (mc *memcacheProbe) Start(_ context.Context, _ component.Host) error {
	return nil
}

func (mc *memcacheProbe) Shutdown(_ context.Context) error {
	return nil
}

func (mc *memcacheProbe) Load(ctx context.Context, reg tracer.ProbeRegistrar, probeCtx *tracer.ProbeContext) (retErr error) {
	// The profiler does not call Unload if Load fails, so release everything
	// that was acquired up to the point of failure.
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, mc.Unload())
		}
	}()

	cpus, err := getOnlineCPUIDs()
	if err != nil {
		return err
	}

	sample, freq := mc.cfg.sampling()
	attr := perf.Attr{
		Type:   perf.HardwareCacheEvent,
		Sample: sample,
		Options: perf.Options{
			Disabled:      true,
			ExcludeKernel: true,
			Freq:          freq,
		},
	}
	for _, ev := range mc.cfg.cacheEvents() {
		ep := &eventProbe{}
		// Track the event right away so Unload releases it on any failure.
		mc.probes = append(mc.probes, ep)

		if err := ep.load(probeCtx, ev, attr, cpus); err != nil {
			return fmt.Errorf("event %s: %w", ev.name, err)
		}
	}

	return nil
}

func (ep *eventProbe) load(probeCtx *tracer.ProbeContext, ev cacheEvent, attr perf.Attr, cpus []int) error {
	ref, err := probeCtx.RegisterCollectTrampoline(&samples.TypeMetadata{
		SampleTypes:  []samples.SampleType{{Type: ev.name, Unit: "count"}},
		ReportValues: true,
		AppendValues: samples.AppendFirstContextValue,
	}, tracer.ProbePerfEvent)
	if err != nil {
		return err
	}
	ep.ref = ref

	spec, err := loadMemcache()
	if err != nil {
		return err
	}

	tailCallMap, err := cebpf.NewMap(spec.Maps[memcacheMapMemcacheTrampoline])
	if err != nil {
		return err
	}
	// The collection works on its own clone of the map.
	defer tailCallMap.Close()

	if err := ref.InsertInto(tailCallMap, 0); err != nil {
		return err
	}

	coll, err := cebpf.NewCollectionWithOptions(spec, cebpf.CollectionOptions{
		MapReplacements: map[string]*cebpf.Map{
			memcacheMapMemcacheValue:      ref.CtxMap,
			memcacheMapMemcacheTrampoline: tailCallMap,
		},
	})
	if err != nil {
		return err
	}
	ep.coll = coll

	attr.Config = ev.config

	prog := coll.Programs[memcacheProgReadPerfEventHook]
	progFD := uint32(prog.FD())

	for _, cpu := range cpus {
		perfEvent, err := perf.Open(&attr, perf.AllThreads, cpu, nil)
		if err != nil {
			return fmt.Errorf("failed to open perf event on CPU %d: %w", cpu, err)
		}
		// Track the event right away so close releases it on any later failure.
		ep.events = append(ep.events, perfEvent)

		if err := perfEvent.SetBPF(progFD); err != nil {
			return fmt.Errorf("failed to attach eBPF program to perf event: %w", err)
		}

		if err := perfEvent.Enable(); err != nil {
			return fmt.Errorf("failed to enable perf event on CPU %d: %w", cpu, err)
		}
	}

	return nil
}

func (ep *eventProbe) close() error {
	for _, ev := range ep.events {
		ev.Disable()
		ev.Close()
	}
	ep.events = nil

	if ep.coll != nil {
		ep.coll.Close()
		ep.coll = nil
	}
	if ep.ref != nil {
		err := ep.ref.Close()
		ep.ref = nil
		return err
	}

	return nil
}

func (mc *memcacheProbe) Unload() error {
	var errs []error
	for _, ep := range mc.probes {
		errs = append(errs, ep.close())
	}
	mc.probes = nil

	return errors.Join(errs...)
}
