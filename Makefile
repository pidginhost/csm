.PHONY: build build-linux build-all clean test lint fmt fmt-check vet ci tools sync-embedded check-embedded

BINARY_NAME := csm
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -s -w -X main.Version=$(VERSION) -X main.BuildHash=$(BUILD_HASH) -X main.BuildTime=$(BUILD_TIME)
GOBIN := $(shell go env GOPATH)/bin
CACHE_DIR ?= $(CURDIR)/.cache
GOCACHE ?= $(CACHE_DIR)/go-build
GOMODCACHE ?= $(CACHE_DIR)/go-mod
GOLANGCI_LINT_CACHE ?= $(CACHE_DIR)/golangci-lint

export GOCACHE
export GOMODCACHE
export GOLANGCI_LINT_CACHE

# sync-embedded copies scripts/deploy.sh into the embedded-configs directory
# so the binary ships an up-to-date copy. The daemon rewrites /opt/csm/deploy.sh
# on every startup from this embedded copy — without this sync, operators see
# their deploy.sh silently revert after the daemon restarts.
sync-embedded:
	@cp scripts/deploy.sh internal/daemon/configs/deploy.sh

# check-embedded verifies the embedded deploy.sh matches scripts/deploy.sh.
# Run in CI to catch drift.
check-embedded:
	@if ! cmp -s scripts/deploy.sh internal/daemon/configs/deploy.sh; then \
		echo "ERROR: internal/daemon/configs/deploy.sh is out of sync with scripts/deploy.sh"; \
		echo "Run 'make sync-embedded' to fix."; \
		exit 1; \
	fi

# Build native binary
build: sync-embedded
	go build -tags yara -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME) ./cmd/csm/

# Build static Linux amd64 binary (production target)
build-linux: sync-embedded
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags yara -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-amd64 ./cmd/csm/

# Build all targets
build-all: build-linux
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -tags yara -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-arm64 ./cmd/csm/

# Run tests with race detector
test:
	go test -v -race -short ./...

# Run linter
lint:
	$(GOBIN)/golangci-lint run --timeout 5m

# Run go vet
vet:
	go vet ./...

# Format code
fmt:
	gofmt -w -s .
	@test -f $(GOBIN)/goimports && $(GOBIN)/goimports -w -local github.com/pidginhost/csm . || true

# Check formatting (fails if not formatted)
fmt-check:
	@test -z "$$(gofmt -l .)" || (echo "Files not formatted:" && gofmt -l . && exit 1)

# Run all CI checks locally
ci: check-embedded fmt-check vet lint test build-linux

# Install dev tools
tools:
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Clean build artifacts
clean:
	rm -rf dist/
	go clean
