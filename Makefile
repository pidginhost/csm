.PHONY: build build-linux build-all clean test lint fmt fmt-check vet ci tools deploy install-remote

BINARY_NAME := csm
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -s -w -X main.Version=$(VERSION) -X main.BuildHash=$(BUILD_HASH) -X main.BuildTime=$(BUILD_TIME)
GOBIN := $(shell go env GOPATH)/bin

# Build native binary
build:
	go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME) ./cmd/csm/

# Build static Linux amd64 binary (production target)
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-amd64 ./cmd/csm/

# Build all targets
build-all: build-linux
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-arm64 ./cmd/csm/

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
	@test -f $(GOBIN)/goimports && $(GOBIN)/goimports -w -local github.com/pidginhost/cpanel-security-monitor . || true

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

# Deploy binary to server (local build, scp): make deploy SERVER=cluster6
deploy: build-linux
	@if [ -z "$(SERVER)" ]; then echo "Usage: make deploy SERVER=hostname"; exit 1; fi
	scp dist/$(BINARY_NAME)-linux-amd64 $(SERVER):/tmp/$(BINARY_NAME)
	ssh $(SERVER) "chmod +x /tmp/$(BINARY_NAME) && /tmp/$(BINARY_NAME) version"
	@echo ""
	@echo "Binary deployed to $(SERVER):/tmp/$(BINARY_NAME)"
	@echo "To install: ssh $(SERVER) '/tmp/$(BINARY_NAME) install'"

# Deploy + install (local build, scp): make install-remote SERVER=cluster6
install-remote: build-linux
	@if [ -z "$(SERVER)" ]; then echo "Usage: make install-remote SERVER=hostname"; exit 1; fi
	scp dist/$(BINARY_NAME)-linux-amd64 $(SERVER):/tmp/$(BINARY_NAME)
	ssh $(SERVER) "chmod +x /tmp/$(BINARY_NAME) && chattr -i /opt/csm/csm 2>/dev/null; /tmp/$(BINARY_NAME) install"

# Upgrade existing (local build, scp): make upgrade SERVER=cluster6
upgrade: build-linux
	@if [ -z "$(SERVER)" ]; then echo "Usage: make upgrade SERVER=hostname"; exit 1; fi
	scp dist/$(BINARY_NAME)-linux-amd64 $(SERVER):/tmp/$(BINARY_NAME)
	ssh $(SERVER) "chmod +x /tmp/$(BINARY_NAME) && chattr -i /opt/csm/csm 2>/dev/null; cp /tmp/$(BINARY_NAME) /opt/csm/csm && chattr +i /opt/csm/csm && /opt/csm/csm version && /opt/csm/csm baseline"
	@echo "Upgrade complete on $(SERVER)"

# Deploy from GitLab CI artifacts: make gitlab-deploy SERVER=cluster6 GITLAB_TOKEN=xxx
gitlab-deploy:
	@if [ -z "$(SERVER)" ]; then echo "Usage: make gitlab-deploy SERVER=cluster6 GITLAB_TOKEN=xxx [REF=main]"; exit 1; fi
	@if [ -z "$(GITLAB_TOKEN)" ]; then echo "GITLAB_TOKEN required"; exit 1; fi
	scp scripts/deploy.sh $(SERVER):/tmp/csm-deploy.sh
	ssh $(SERVER) "chmod +x /tmp/csm-deploy.sh && GITLAB_TOKEN=$(GITLAB_TOKEN) /tmp/csm-deploy.sh install $(or $(REF),main)"

# Upgrade from GitLab CI artifacts: make gitlab-upgrade SERVER=cluster6
gitlab-upgrade:
	@if [ -z "$(SERVER)" ]; then echo "Usage: make gitlab-upgrade SERVER=cluster6 [REF=main]"; exit 1; fi
	scp scripts/deploy.sh $(SERVER):/tmp/csm-deploy.sh
	ssh $(SERVER) "chmod +x /tmp/csm-deploy.sh && /tmp/csm-deploy.sh upgrade $(or $(REF),main)"
