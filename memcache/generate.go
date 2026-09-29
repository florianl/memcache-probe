package memcache

//go:generate go tool bpf2go -target amd64,arm64 memcache ../bpf/memcache.ebpf.c -- -I../bpf/headers
