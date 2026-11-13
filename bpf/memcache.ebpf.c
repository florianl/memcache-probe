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

#if defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
typedef struct user_pt_regs bpf_user_pt_regs_t;
#else
typedef struct pt_regs bpf_user_pt_regs_t;
#endif

// Matches the UAPI definition in <linux/bpf_perf_event.h>.
struct bpf_perf_event_data {
	bpf_user_pt_regs_t regs;
	__u64 sample_period;
	__u64 addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(int));
} l1d_read_miss SEC(".maps");

SEC("perf_event")
int read_perf_event_hook(struct bpf_perf_event_data *ctx) {
    // Every overflow of the counter stands for sample_period cache misses.
    // The counter itself is a running total for the whole CPU and must not be
    // reported as the value of a single sample.
    __u64 normalized = ctx->sample_period;

    // val.enabled -> Total time event was enabled (ns)
    // val.running -> Total time event was actually on CPU (ns)
    struct bpf_perf_event_value val = {};
    int ret = bpf_perf_event_read_value(&l1d_read_miss, BPF_F_CURRENT_CPU, &val, sizeof(val));
    if (ret == 0 && val.running > 0) {
        normalized = normalized * (val.enabled / val.running);
    }

    __u32 key = 0;
    bpf_map_update_elem(&memcache_value, &key, &normalized, BPF_ANY);
    bpf_printk("L1D miss sample: normalized=%llu (period=%llu)", normalized, ctx->sample_period);
    bpf_tail_call(ctx, &memcache_trampoline, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";