package memcache

import (
	"slices"
	"strings"
	"testing"
)

func TestConfigValidate(t *testing.T) {
	tests := map[string]struct {
		cfg     Config
		wantErr bool
	}{
		"default":         {cfg: *createDefaultConfig()},
		"several events":  {cfg: Config{Event: []string{"LLC-loads", "LLC-load-misses", "L1-dcache-store-misses"}}},
		"lower case":      {cfg: Config{Event: []string{"llc-stores"}}},
		"count":           {cfg: Config{Event: []string{"LLC-load-misses"}, Count: 10000}},
		"freq":            {cfg: Config{Event: []string{"LLC-load-misses"}, Freq: 99}},
		"max count":       {cfg: Config{Event: []string{"LLC-load-misses"}, Count: maxCount}},
		"count too large": {cfg: Config{Event: []string{"LLC-load-misses"}, Count: maxCount + 1}, wantErr: true},
		"count overflow":  {cfg: Config{Event: []string{"LLC-load-misses"}, Count: 1 << 63}, wantErr: true},
		"no event":        {cfg: Config{}, wantErr: true},
		"unknown event":   {cfg: Config{Event: []string{"L2-dcache-load-misses"}}, wantErr: true},
		"other hw event":  {cfg: Config{Event: []string{"cycles"}}, wantErr: true},
		"duplicate event": {cfg: Config{Event: []string{"LLC-loads", "llc-loads"}}, wantErr: true},
		"count and freq":  {cfg: Config{Event: []string{"LLC-loads"}, Count: 1000, Freq: 99}, wantErr: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestCacheEvents(t *testing.T) {
	names := []string{
		"L1-dcache-loads", "L1-dcache-load-misses", "L1-dcache-stores", "L1-dcache-store-misses",
		"LLC-loads", "LLC-load-misses", "LLC-stores", "LLC-store-misses",
	}

	var cfg Config
	for _, name := range names {
		cfg.Event = append(cfg.Event, strings.ToLower(name))
	}
	want := []uint64{0x0, 0x10000, 0x100, 0x10100, 0x2, 0x10002, 0x102, 0x10102}

	var got []uint64
	var gotNames []string
	for _, ev := range cfg.cacheEvents() {
		got = append(got, ev.config)
		gotNames = append(gotNames, ev.name)
	}
	if !slices.Equal(gotNames, names) {
		t.Fatalf("cacheEvents() names = %v, want %v", gotNames, names)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("cacheEvents() configs = %#x, want %#x", got, want)
	}
}

func TestSampling(t *testing.T) {
	tests := map[string]struct {
		cfg       Config
		wantValue uint64
		wantFreq  bool
	}{
		"default": {cfg: Config{}, wantValue: defaultCount},
		"count":   {cfg: Config{Count: 5000}, wantValue: 5000},
		"freq":    {cfg: Config{Freq: 99}, wantValue: 99, wantFreq: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			value, freq := tc.cfg.sampling()
			if value != tc.wantValue || freq != tc.wantFreq {
				t.Fatalf("sampling() = %d, %t, want %d, %t", value, freq, tc.wantValue, tc.wantFreq)
			}
		})
	}
}
