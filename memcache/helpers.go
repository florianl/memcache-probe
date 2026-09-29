package memcache

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"go.opentelemetry.io/ebpf-profiler/stringutil"
)

// getOnlineCPUIDs reads online CPUs from /sys/devices/system/cpu/online and reports
// the core IDs as a list of integers. You should probably use `onlineCPUsOnce` instead.
func getOnlineCPUIDs() ([]int, error) {
	cpuPath := "/sys/devices/system/cpu/online"
	buf, err := os.ReadFile(cpuPath)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %v", cpuPath, err)
	}
	return readCPURange(string(buf))
}

// Since the format of online CPUs can contain comma-separated, ranges or a single value
// we need to try and parse it in all its different forms.
// Reference: https://www.kernel.org/doc/Documentation/admin-guide/cputopology.rst
func readCPURange(cpuRangeStr string) ([]int, error) {
	if cpuRangeStr == "" {
		return []int{}, nil
	}
	var cpus []int
	cpuRangeStr = strings.Trim(cpuRangeStr, "\n ")
	for cpuRange := range strings.SplitSeq(cpuRangeStr, ",") {
		var rangeOp [2]string
		nParts := stringutil.SplitN(cpuRange, "-", rangeOp[:])
		first, err := strconv.ParseUint(rangeOp[0], 10, 32)
		if err != nil {
			return nil, err
		}
		if nParts == 1 {
			cpus = append(cpus, int(first))
			continue
		}
		last, err := strconv.ParseUint(rangeOp[1], 10, 32)
		if err != nil {
			return nil, err
		}
		if first > last {
			return nil, fmt.Errorf("invalid CPU range %q: start > end", cpuRange)
		}
		for n := first; n <= last; n++ {
			cpus = append(cpus, int(n))
		}
	}
	return cpus, nil
}

// Constants matching <linux/perf_event.h>
const (
	// Cache IDs
	PerfHWCacheL1D = 0 // L1 Data
	PerfHWCacheLLC = 2 // Last Level Cache (L3)

	// Cache Operations
	PerfHWCacheOpRead  = 0
	PerfHWCacheOpWrite = 1

	// Cache Results
	PerfHWCacheResultAccess = 0 // Total references/accesses
	PerfHWCacheResultMiss   = 1 // Misses
)

// Helper to calculate the packed config value
func makeCacheConfig(cache, op, result uint64) uint64 {
	return cache | (op << 8) | (result << 16)
}
