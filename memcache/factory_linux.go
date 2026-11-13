//go:build linux && (amd64 || arm64)

package memcache // import "github.com/florianl/memcache-probe/memcache"

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
)

func NewFactory() extension.Factory {
	return extension.NewFactory(
		Type,
		func() component.Config { return createDefaultConfig() },
		createExtension,
		stability,
	)
}

func createExtension(_ context.Context, _ extension.Settings, cfg component.Config) (extension.Extension, error) {
	return &memcacheProbe{cfg: cfg.(*Config)}, nil
}
