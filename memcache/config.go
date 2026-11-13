package memcache

import (
	"errors"
	"fmt"
	"strings"
)

// Constants matching <linux/perf_event.h>
const (
	// Cache IDs
	perfHWCacheL1D = 0 // L1 Data
	perfHWCacheLLC = 2 // Last Level Cache (L3)

	// Cache Operations
	perfHWCacheOpRead  = 0
	perfHWCacheOpWrite = 1

	// Cache Results
	perfHWCacheResultAccess = 0 // Total references/accesses
	perfHWCacheResultMiss   = 1 // Misses
)

// defaultCount is the sample period used if neither count nor freq is set:
// 4096 << 8 = 2^20 = 1048576, so one sample stands for about a million events.
const defaultCount = 4096 << 8

// Supported events, named as in `perf list`.
var supportedEvents = []cacheEvent{
	{"L1-dcache-loads", makeCacheConfig(perfHWCacheL1D, perfHWCacheOpRead, perfHWCacheResultAccess)},
	{"L1-dcache-load-misses", makeCacheConfig(perfHWCacheL1D, perfHWCacheOpRead, perfHWCacheResultMiss)},
	{"L1-dcache-stores", makeCacheConfig(perfHWCacheL1D, perfHWCacheOpWrite, perfHWCacheResultAccess)},
	{"L1-dcache-store-misses", makeCacheConfig(perfHWCacheL1D, perfHWCacheOpWrite, perfHWCacheResultMiss)},
	{"LLC-loads", makeCacheConfig(perfHWCacheLLC, perfHWCacheOpRead, perfHWCacheResultAccess)},
	{"LLC-load-misses", makeCacheConfig(perfHWCacheLLC, perfHWCacheOpRead, perfHWCacheResultMiss)},
	{"LLC-stores", makeCacheConfig(perfHWCacheLLC, perfHWCacheOpWrite, perfHWCacheResultAccess)},
	{"LLC-store-misses", makeCacheConfig(perfHWCacheLLC, perfHWCacheOpWrite, perfHWCacheResultMiss)},
}

func lookupEvent(name string) (cacheEvent, bool) {
	for _, ev := range supportedEvents {
		if strings.EqualFold(ev.name, name) {
			return ev, true
		}
	}
	return cacheEvent{}, false
}

// Config holds the YAML configuration for the memcache probe. The options
// follow the long options of `perf record`.
//
//	extensions:
//	  memcache:
//	    event: [L1-dcache-load-misses]  # perf record -e
//	    count: 1048576                  # perf record -c
//	    # freq: 99                      # perf record -F, instead of count
type Config struct {
	Event []string `mapstructure:"event"`
	Count uint64   `mapstructure:"count"`
	Freq  uint64   `mapstructure:"freq"`
}

func createDefaultConfig() *Config {
	return &Config{
		Event: []string{"L1-dcache-load-misses"},
	}
}

// Validate implements confmap.Validator.
func (c *Config) Validate() error {
	var errs []error
	if len(c.Event) == 0 {
		errs = append(errs, fmt.Errorf("memcache: event must list at least one of %v", validEvents()))
	}
	seen := make(map[string]struct{}, len(c.Event))
	for _, ev := range c.Event {
		found, ok := lookupEvent(ev)
		if !ok {
			errs = append(errs, fmt.Errorf("memcache: invalid event %q, must be one of %v", ev, validEvents()))
			continue
		}
		name := found.name
		if _, dup := seen[name]; dup {
			errs = append(errs, fmt.Errorf("memcache: event %q is listed more than once", ev))
		}
		seen[name] = struct{}{}
	}
	if c.Count != 0 && c.Freq != 0 {
		errs = append(errs, errors.New("memcache: count and freq can not be used together"))
	}
	return errors.Join(errs...)
}

type cacheEvent struct {
	name   string
	config uint64
}

func (c *Config) cacheEvents() []cacheEvent {
	events := make([]cacheEvent, 0, len(c.Event))
	for _, ev := range c.Event {
		if found, ok := lookupEvent(ev); ok {
			events = append(events, found)
		}
	}
	return events
}

func (c *Config) sampling() (value uint64, freq bool) {
	switch {
	case c.Freq != 0:
		return c.Freq, true
	case c.Count != 0:
		return c.Count, false
	default:
		return defaultCount, false
	}
}

func makeCacheConfig(cache, op, result uint64) uint64 {
	return cache | (op << 8) | (result << 16)
}

func validEvents() []string {
	names := make([]string, 0, len(supportedEvents))
	for _, ev := range supportedEvents {
		names = append(names, ev.name)
	}
	return names
}
