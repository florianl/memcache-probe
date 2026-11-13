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

// The multiplexing ratio is taken over a window of at least this much enabled
// time. The kernel rotates events every few milliseconds, so the window spans
// many rotations and all samples in it are scaled by about the same factor.
#define MUX_WINDOW_NS 100000000ULL

// Enabled and running time of the perf event at the start of the current and
// of the previous window on this CPU. Every event has its own instance of the
// program and so of this map.
struct mux_window {
    __u64 prev_enabled;
    __u64 prev_running;
    __u64 cur_enabled;
    __u64 cur_running;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mux_window);
} memcache_mux SEC(".maps");

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

// scale_period returns period * enabled / running without overflowing in the
// intermediate product and without giving up the fractional part of the ratio.
// The result only wraps if the scaled period itself does not fit into 64 bits.
static __always_inline __u64 scale_period(__u64 period, __u64 enabled, __u64 running) {
    if (running == 0 || enabled <= running) {
        return period;
    }

    __u64 whole = enabled / running;
    __u64 rem = enabled % running;

    // Bring the remainder and the divisor below 2^32 so the fraction can be
    // calculated as a 32 bit fixed point number. rem < running holds, and at
    // least 16 significant bits of running are kept.
    if (running >> 48) {
        rem >>= 16;
        running >>= 16;
    }
    if (running >> 32) {
        rem >>= 16;
        running >>= 16;
    }
    __u64 frac = (rem << 32) / running;

    return period * whole + (period >> 32) * frac + (((period & 0xffffffffULL) * frac) >> 32);
}

SEC("perf_event")
int read_perf_event_hook(struct bpf_perf_event_data *ctx) {
    // Every overflow of the counter stands for sample_period cache events.
    // The counter itself is a running total for the whole CPU and must not be
    // reported as the value of a single sample.
    __u64 normalized = ctx->sample_period;

    __u32 key = 0;

    // val.enabled -> Total time event was enabled (ns)
    // val.running -> Total time event was actually on CPU (ns)
    struct bpf_perf_event_value val = {};
    // Reads the perf event that triggered this program.
    int ret = bpf_perf_prog_read_value(ctx, &val, sizeof(val));
    struct mux_window *win = bpf_map_lookup_elem(&memcache_mux, &key);
    if (ret == 0 && win) {
        if (val.enabled < win->cur_enabled || val.running < win->cur_running) {
            // The times went backwards, start over from this sample.
            win->prev_enabled = win->cur_enabled = val.enabled;
            win->prev_running = win->cur_running = val.running;
        } else {
            // Scale up for the time the event was multiplexed off the PMU.
            // The ratio is taken from the start of the previous window up to
            // this sample, which covers one to two windows. The interval
            // since the previous sample alone would put the whole off time on
            // the first sample after the event got back on the PMU, and the
            // totals since the event was enabled would not follow changes in
            // multiplexing.
            normalized = scale_period(normalized, val.enabled - win->prev_enabled,
                                      val.running - win->prev_running);
            if (val.enabled - win->cur_enabled >= MUX_WINDOW_NS) {
                win->prev_enabled = win->cur_enabled;
                win->prev_running = win->cur_running;
                win->cur_enabled = val.enabled;
                win->cur_running = val.running;
            }
        }
    }

    bpf_map_update_elem(&memcache_value, &key, &normalized, BPF_ANY);
    bpf_printk("cache event sample: normalized=%llu (period=%llu)", normalized, ctx->sample_period);
    bpf_tail_call(ctx, &memcache_trampoline, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";