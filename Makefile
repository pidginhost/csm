.PHONY: build build-linux build-all clean test lint sec vuln fmt fmt-check vet ci tools sync-embedded check-embedded

# Pinned tool versions -- bump deliberately, keep in sync with .gitlab-ci.yml
GOLANGCI_LINT_VERSION := v2.11.4
GOSEC_VERSION := v2.25.0
GOVULNCHECK_VERSION := v1.2.0

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

# Static security analysis. -exclude=G104 because golangci-lint's errcheck
# already handles unhandled errors with a curated exclude-functions list
# (see .golangci.yml); running both duplicates without coordinated filtering.
sec:
	$(GOBIN)/gosec -exclude=G104 -exclude-dir=e2e -exclude-dir=scripts ./...

# Vulnerability scan
vuln:
	$(GOBIN)/govulncheck ./...

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
ci: check-embedded fmt-check vet lint sec vuln test build-linux

# Install dev tools (versions pinned at top of Makefile)
tools:
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

# Clean build artifacts
clean:
	rm -rf dist/
	go clean
