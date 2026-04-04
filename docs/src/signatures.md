# Signature Rules

CSM uses YAML and YARA-X rules for malware detection. Rules are stored in `/opt/csm/rules/` and scanned both in real-time (fanotify) and during deep scans.

## YAML Rules

```yaml
rules:
  - name: webshell_c99
    severity: critical
    category: webshell
    file_types: [".php"]
    patterns: ["c99shell", "c99_buff_prepare"]
    min_match: 1

  - name: phishing_login
    severity: high
    category: phishing
    file_types: [".html", ".php"]
    patterns: ["password.*submit", "credit.*card.*number"]
    exclude: ["legitimate_form_handler"]
    min_match: 2
```

**Fields:**
- `name` — unique rule identifier
- `severity` — critical, high, or warning
- `category` — webshell, backdoor, phishing, dropper, exploit
- `file_types` — file extensions to match (or `["*"]` for all)
- `patterns` — literal strings or regex patterns
- `exclude` — patterns that prevent a match (false positive reduction)
- `min_match` — minimum patterns that must match

## YARA-X Rules (Optional)

Build CSM with YARA-X support:

```bash
CGO_LDFLAGS="$(pkg-config --libs --static yara_x_capi)" go build -tags yara ./cmd/csm/
```

Place `.yar` or `.yara` files alongside YAML rules in `/opt/csm/rules/`. CSM compiles them at startup and uses them for:
- Real-time fanotify file scanning
- Deep scan filesystem sweeps
- Email attachment scanning

Without the `yara` build tag, YARA rules are silently ignored.

## Updating Rules

```bash
csm update-rules          # download latest rules from registry
kill -HUP $(pidof csm)    # reload without restart
```

Or from the web UI: **Rules** page > **Reload Rules** button.

## Suppressions

Create suppression rules to silence known false positives:

- From the **Findings** page: click the suppress button on any finding
- From the **Rules** page: manage suppression rules directly
- Via API: `POST /api/v1/suppressions`
