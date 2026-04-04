# CSM — Continuous Security Monitor

## Project Overview

CSM is a real-time security monitoring daemon for cPanel/WHM servers. It watches log files, filesystem events (fanotify), and system state to detect attacks, webshells, brute force, phishing kits, and malware — then auto-responds (block IPs, quarantine files, kill processes) and alerts operators via email, webhooks, and a web dashboard.

**Module:** `github.com/pidginhost/csm`
**Language:** Go 1.26+ (single binary, CGO optional for YARA-X)
**Target OS:** Linux (cPanel/WHM servers — CentOS, AlmaLinux, CloudLinux)
**Binary name:** `csm`
**Config:** `/opt/csm/csm.yaml`
**State:** bbolt DB at `/opt/csm/state/`

## Architecture

```
cmd/csm/           — CLI entrypoint (daemon, install, uninstall, scan)
internal/
  daemon/           — Main daemon loop, log watchers, check orchestration
  checks/           — Security check implementations (waf, webshell, permissions, etc.)
  config/           — YAML config parsing
  store/            — bbolt persistent storage (findings, threat DB, hit counters)
  state/            — In-memory state (findings, stats, history ring buffer)
  webui/            — HTTPS web UI server (Go templates + vanilla JS)
  firewall/         — nftables firewall management
  modsec/           — ModSecurity config parser, overrides, reload
  alert/            — Email/webhook alert dispatch
  geoip/            — MaxMind GeoIP lookups
  signatures/       — YAML signature scanner
  yara/             — YARA-X scanner (build tag: yara)
  emailav/          — Email attachment AV scanning
  attackdb/         — Attack database (IP reputation tracking)
  threat/           — Threat intelligence aggregation
  challenge/        — JavaScript challenge pages (CAPTCHA alternative)
  integrity/        — Binary/config integrity verification
  wpcheck/          — WordPress core file checksum verification
  auditd/           — Audit log for admin actions
ui/
  templates/        — Go HTML templates (Tabler CSS framework)
  static/js/        — Vanilla JavaScript (no build step, no framework)
  static/css/       — CSS (Tabler + csm.css custom styles)
configs/            — Embedded configs (modsec rules, malware sigs, WHM plugin)
```

## Build & Test

```bash
# Standard build (no YARA-X)
go build ./cmd/csm/

# Build with YARA-X support (requires libyara_x_capi)
CGO_LDFLAGS="$(pkg-config --libs --static yara_x_capi)" go build -tags yara ./cmd/csm/

# Run tests
go test ./... -count=1
go test -race -short ./...    # CI mode

# Lint (must pass before push)
golangci-lint run --timeout 5m
gofmt -l .                    # must produce no output
```

## CI/CD Pipeline

**GitLab CI** at `.gitlab-ci.yml`. Stages: lint → test → build → package → publish → cleanup.

- **lint:** golangci-lint + gofmt check
- **test:** `go test -v -race -short ./...`
- **build:** Two architectures (amd64 with YARA-X CGO, arm64 pure Go)
- **package:** RPM + DEB via nFPM
- **publish:** GitLab Generic Package Registry (versioned + `latest`)
- **release:** On tags matching `v*`

## Deployment

**NEVER scp files directly to servers.** Always:
1. `git commit` + `git push`
2. Wait for CI pipeline to pass
3. Deploy from package registry via `deploy.sh upgrade` on the server

The CI pipeline builds, tests, lints, packages, and publishes. Production servers pull from the registry.

## Code Conventions

### Go
- **Linter config:** `.golangci.yml` — errcheck, govet, staticcheck, unused, ineffassign, gocritic, misspell, bodyclose, nilerr
- **Imports:** stdlib → blank line → third-party → blank line → internal packages. Use `goimports` with `-local github.com/pidginhost/csm`
- **Error handling:** Return errors up the call stack. Use `fmt.Errorf("context: %w", err)` for wrapping
- **Store pattern:** `store.Global()` returns the singleton bbolt DB. Nil-safe — always check `if db := store.Global(); db != nil`
- **State pattern:** `state.Store` is the in-memory findings/stats store, passed to subsystems at init
- **Config:** Single `config.Config` struct parsed from YAML, passed by pointer
- **No generics abuse** — keep it simple, idiomatic Go

### Web UI (JavaScript)
- **Vanilla JS** — no framework, no build step, no npm
- **CSS framework:** Tabler (Bootstrap-based), loaded from `/static/css/`
- **Charts:** Chart.js loaded from `/static/js/chart.min.js`
- **CSM namespace:** All shared helpers live on the global `CSM` object (defined in `csrf.js`)
- **API URL routing:** ALL fetch/API calls MUST use `CSM.apiUrl('/api/v1/...')` for GET requests and `CSM.post('/api/v1/...', body)` for POST. This is required for WHM CGI proxy support (`addon_csm.cgi` rewrites)
- **CSRF:** POST requests require X-CSRF-Token header. `CSM.post()` handles this automatically
- **HTML escaping:** Always use `CSM.esc(value)` when inserting user data into HTML
- **Templates:** Go `html/template` with layout inheritance. Each page defines `title`, `page`, `content`, `scripts` blocks

### Security
- Auth via Bearer token or cookie (`csm_auth`). CSRF on all POST endpoints
- Rate limiting: 5 login attempts/min, 600 API requests/min per IP
- All API endpoints behind `requireAuth` middleware
- POST mutations behind `requireCSRF` middleware
- CSP headers: `default-src 'self'; script-src 'self' 'unsafe-inline'`

## Key Patterns

### Adding a new API endpoint
1. Create handler in `internal/webui/` (or add to existing file)
2. Register route in `server.go` `New()` — GET: `s.requireAuth(http.HandlerFunc(...))`, POST: add `s.requireCSRF(...)`
3. Use `writeJSON(w, data)` and `writeJSONError(w, msg, code)` helpers

### Adding a new page
1. Create template in `ui/templates/page.html` with `title`, `page`, `content`, `scripts` blocks
2. Create JS in `ui/static/js/page.js`
3. Add page name to template list in `server.go` (the `for _, page := range []string{...}` loop)
4. Register HTML route and API routes in `server.go`

### ModSecurity rules
- CSM custom rules: IDs 900000-900999 in `configs/csm_modsec_custom.conf`
- Parser: `internal/modsec/parser.go`
- Overrides: `SecRuleRemoveById` directives managed via `internal/modsec/overrides.go`
- Deploy: Both `installer.go:DeployModSecRules()` and `daemon.go:deployConfigs()` write rules + append overrides Include

### YARA-X
- Use VirusTotal's `github.com/VirusTotal/yara-x/go` (NOT hillu/go-yara)
- Build tag: `yara` — code behind `//go:build yara` constraints
- Scanner init: `yara.Init(rulesDir)` returns nil if build tag absent
