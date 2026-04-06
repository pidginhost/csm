.PHONY: build build-linux build-all clean test lint fmt fmt-check vet ci tools

BINARY_NAME := csm
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -s -w -X main.Version=$(VERSION) -X main.BuildHash=$(BUILD_HASH) -X main.BuildTime=$(BUILD_TIME)
GOBIN := $(shell go env GOPATH)/bin

# Build native binary
build:
	go build -tags yara -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME) ./cmd/csm/

# Build static Linux amd64 binary (production target)
build-linux:
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
ci: fmt-check vet lint test build-linux

# Install dev tools
tools:
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Clean build artifacts
clean:
	rm -rf dist/
	go clean

