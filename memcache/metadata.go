package memcache

import "go.opentelemetry.io/collector/component"

var (
	Type      = component.MustNewType("memcache")
	stability = component.StabilityLevelDevelopment
)
