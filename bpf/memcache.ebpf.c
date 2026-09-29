// SPDX-License-Identifier: GPL-2.0

#include "common.h"

// Single-entry prog array populated at load time with the kernel program ID
// of the collect trampoline (CollectTrampolineRef.TailCallDestinationID).
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} memcache_trampoline SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} memcache_value SEC(".maps");

// TODO: Check if this struct can be used from the included headers.
struct bpf_perf_event_value {
	__u64 counter;
	__u64 enabled;
	__u64 running;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(int));
} l1d_read_miss SEC(".maps");

SEC("perf_event")
int read_perf_event_hook(struct bpf_perf_event_data *ctx) {
    struct bpf_perf_event_value val = {};

    int ret = bpf_perf_event_read_value(&l1d_read_miss, BPF_F_CURRENT_CPU, &val, sizeof(val));
    if (ret != 0) {
        return 0;
    }

    // val.counter -> Total L1D cache read misses
    // val.enabled -> Total time event was enabled (ns)
    // val.running -> Total time event was actually on CPU (ns)
    __u64 normalized = val.counter;
    if (val.running > 0) {
        normalized = val.counter * (val.enabled / val.running);
    }

    __u32 key = 0;
    bpf_map_update_elem(&memcache_value, &key, &normalized, BPF_ANY);
    bpf_printk("L1D miss sample: normalized=%llu (counter=%llu)", normalized, val.counter);
    bpf_tail_call(ctx, &memcache_trampoline, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";