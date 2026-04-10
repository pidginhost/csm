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
make lint                        # must pass before push
gofmt -l .                       # must produce no output
```

`make lint` uses repo-local cache directories under `.cache/` so the command behaves consistently in local shells, sandboxes, and CI runners.

Linter config in `.golangci.yml`: errcheck, govet, staticcheck, unused, ineffassign, gocritic, misspell, bodyclose, nilerr.

## CI/CD

GitLab CI (`.gitlab-ci.yml`) is the internal build pipeline. It runs lint/test/package jobs, publishes internal packages, mirrors to GitHub, and creates the public GitHub release artifacts.

| Stage | What it does |
|-------|-------------|
| **lint** | golangci-lint + gofmt check |
| **test** | `go test -v -race -short ./...` |
| **build-image** | Build CSM builder Docker image with YARA-X (manual trigger) |
| **build** | Two architectures (amd64 with YARA-X CGO, arm64 pure Go) |
| **package** | RPM + DEB via nFPM |
| **publish** | Internal GitLab Generic Package Registry (versioned + `latest`) |
| **cleanup** | Clean old package versions |
| **release** | GitLab release on tags matching `v*` |

## Public Releases

Public installs and upgrades use GitHub Releases:

1. Push changes and create a release tag.
2. Let CI build and publish the release artifacts.
3. Install or upgrade with `/opt/csm/deploy.sh install` or `/opt/csm/deploy.sh upgrade`.

The GitLab package registry and any GitLab-only deploy helpers are internal operational tooling, not part of the public GitHub workflow.

## Code Conventions

- **Imports:** stdlib, blank line, third-party, blank line, internal. Use `goimports -local github.com/pidginhost/csm`
- **Errors:** Return up the call stack. Wrap with `fmt.Errorf("context: %w", err)`
- **Store:** `store.Global()` singleton bbolt DB. Always nil-check.
- **State:** `state.Store` handles finding dedup, alert throttling, baseline tracking, latest findings persistence. Passed to subsystems at init
- **Web UI:** Vanilla JS, no framework, no build step. Tabler CSS framework. All API calls via `CSM.apiUrl()` / `CSM.post()`. Escape with `CSM.esc()`.
- **Logging:** New code should use `internal/log` (wraps `log/slog`). Legacy `fmt.Fprintf(os.Stderr, "[%s] ...", ts())` call sites remain valid until migrated.

## Structured Logging (slog)

CSM's daemon emits ~190 log lines via `fmt.Fprintf(os.Stderr, "[%s] ...", ts())`. The `internal/log` package provides a drop-in slog wrapper so operators can opt into JSON output for log-shipping pipelines (Loki, ELK, Datadog) without a big bang migration.

### Operator controls

Two environment variables, read once at daemon startup:

| Variable | Values | Default | Effect |
|----------|--------|---------|--------|
| `CSM_LOG_FORMAT` | `text`, `json` | `text` | Output handler |
| `CSM_LOG_LEVEL` | `debug`, `info`, `warn`, `error` | `info` | Minimum log level |

Set via systemd drop-in:

```ini
# /etc/systemd/system/csm.service.d/logging.conf
[Service]
Environment="CSM_LOG_FORMAT=json"
Environment="CSM_LOG_LEVEL=info"
```

Then `systemctl daemon-reload && systemctl restart csm`.

### Writing new logging code

```go
import csmlog "github.com/pidginhost/csm/internal/log"

csmlog.Info("scan complete", "findings", len(f), "duration_ms", d.Milliseconds())
csmlog.Warn("log not found, will retry", "path", path, "retry_in", "60s")
csmlog.Error("alert dispatch failed", "err", err, "channel", "email")
```

Keys should be snake_case. Values should be machine-parseable (numbers, strings, booleans) — avoid formatted strings when you can pass the raw value.

### Migrating legacy call sites

Migration is incremental and optional. The legacy format stays valid. Start with the hottest subsystems (alert dispatch, firewall operations, WAF handlers) where structured fields provide the most value, then work outward. Do not batch-convert — each subsystem should get a dedicated commit with before/after log samples in the PR description.

Keep the `[TIMESTAMP]` prefix of journalctl lines readable by humans: slog's text handler uses `time=... level=... msg=...` which is also human-parseable, so journalctl viewers still work.

## Building the Documentation

```bash
cd docs
mdbook build              # generates docs/book/
mdbook serve              # local preview at http://localhost:3000
```
