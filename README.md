# memcache-probe

An OpenTelemetry Collector extension that plugs into the
[OpenTelemetry eBPF profiler](https://github.com/open-telemetry/opentelemetry-ebpf-profiler)
and records stack traces where L1 data cache read misses occur. It opens a
hardware cache perf event on every online CPU and triggers the profiler's stack
unwinder whenever the counter overflows.

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
