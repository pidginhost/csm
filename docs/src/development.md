# Building & Testing

## Build

```bash
# Standard build (no YARA-X)
go build ./cmd/csm/

# Build with YARA-X support (requires libyara_x_capi)
CGO_LDFLAGS="$(pkg-config --libs --static yara_x_capi)" go build -tags yara ./cmd/csm/
```

## Test

```bash
go test ./... -count=1           # all tests
go test -race -short ./...       # CI mode (race detector, skip slow tests)
```

## Lint

```bash
golangci-lint run --timeout 5m   # must pass before push
gofmt -l .                       # must produce no output
```

Linter config in `.golangci.yml`: errcheck, govet, staticcheck, unused, ineffassign, gocritic, misspell, bodyclose, nilerr.

## CI/CD

GitLab CI (`.gitlab-ci.yml`). Stages: lint, test, build, package, publish, cleanup.

| Stage | What it does |
|-------|-------------|
| **lint** | golangci-lint + gofmt check |
| **test** | `go test -v -race -short ./...` |
| **build** | Two architectures (amd64 with YARA-X CGO, arm64 pure Go) |
| **package** | RPM + DEB via nFPM |
| **publish** | GitLab Generic Package Registry (versioned + `latest`) |
| **release** | On tags matching `v*` |

## Deployment

**Never scp files directly to servers.** Always:

1. `git commit` + `git push`
2. Wait for CI pipeline to pass
3. Deploy from package registry via `deploy.sh upgrade` on the server

## Code Conventions

- **Imports:** stdlib, blank line, third-party, blank line, internal. Use `goimports -local github.com/pidginhost/csm`
- **Errors:** Return up the call stack. Wrap with `fmt.Errorf("context: %w", err)`
- **Store:** `store.Global()` singleton bbolt DB. Always nil-check.
- **State:** `state.Store` in-memory findings/stats, passed to subsystems at init
- **Web UI:** Vanilla JS, no framework, no build step. Tabler CSS framework. All API calls via `CSM.apiUrl()` / `CSM.post()`. Escape with `CSM.esc()`.

## Building the Documentation

```bash
cd docs
mdbook build              # generates docs/book/
mdbook serve              # local preview at http://localhost:3000
```
