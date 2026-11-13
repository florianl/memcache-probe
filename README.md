# memcache-probe

An OpenTelemetry Collector extension that plugs into the
[OpenTelemetry eBPF profiler](https://github.com/open-telemetry/opentelemetry-ebpf-profiler)
and records stack traces where hardware cache events occur, such as L1 data
cache or last level cache loads, stores and their misses. It opens a perf event
for each configured cache event on every online CPU and triggers the profiler's
stack unwinder whenever the counter overflows.

Status: development. Linux on amd64 and arm64 only.

## Build

Requires Go and clang.

```sh
make otelcol-memcache-profiler
```

The collector binary is written to `dist/otelcol-memcache-probe`.

## Configuration

Enable the extension and reference it from the `profiling` receiver:

```yaml
extensions:
  memcache:
    event: [L1-dcache-load-misses]  # like perf record -e
    count: 1048576                  # like perf record -c

receivers:
  profiling:
    probes:
      - memcache

exporters:
  otlp_grpc:
    endpoint: 127.0.0.1:4317
    tls:
      insecure: true

service:
  extensions: [memcache]
  pipelines:
    profiles:
      receivers: [profiling]
      exporters: [otlp_grpc]
```

The options follow `perf record`:

| Option  | perf | Description |
|---------|------|-------------|
| `event` | `-e` | One or more of `L1-dcache-loads`, `L1-dcache-load-misses`, `L1-dcache-stores`, `L1-dcache-store-misses`, `LLC-loads`, `LLC-load-misses`, `LLC-stores`, `LLC-store-misses`. Each event is exported as its own profile. |
| `count` | `-c` | Sample every N events. Defaults to 1048576 (2^20). |
| `freq`  | `-F` | Sample at this frequency in Hz. Can not be combined with `count`. |

The values shown above are the defaults. Only user space is sampled, as with
the `:u` event modifier. Not every event is supported by every CPU; an
unsupported one fails at startup.

## Run

```sh
sudo ./dist/otelcol-memcache-probe \
  --config=config/config.yaml \
  --feature-gates=+service.profilesSupport
```

The host must expose hardware cache events, which is often not the case
inside virtual machines.

## License

Apache-2.0. The eBPF code in `bpf/` is GPL-2.0.
