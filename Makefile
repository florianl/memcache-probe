.PHONY: fmt lint vulncheck generate otelcol-memcache-profiler clean test

fmt:
	go tool gofumpt -w .

lint:
	go tool staticcheck -checks=all -show-ignored -tests ./...

vulncheck:
	go tool govulncheck ./...

generate:
	go generate ./...

otelcol-memcache-profiler: generate
	go tool builder --config ./manifest.yaml

clean:
	rm -rf dist

test:
	go clean -testcache
	go test ./...