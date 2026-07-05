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
    exclude_patterns: ["legitimate_form_handler"]
    min_match: 2
```

**Fields:**
- `name` - unique rule identifier
- `severity` - critical, high, or warning
- `category` - webshell, backdoor, phishing, dropper, exploit
- `file_types` - file extensions to match (or `["*"]` for all)
- `patterns` - literal strings
- `regexes` - regex patterns
- `exclude_patterns` - literal patterns that suppress a match (false positive reduction)
- `exclude_regexes` - regex patterns that suppress a match
- `min_match` - minimum patterns that must match

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
csm update-rules          # download latest rules and reload the running daemon
```

`csm update-rules` now asks the daemon to reload through the control socket once the download completes. If the daemon is not running, the next start picks the files up automatically. `kill -HUP $(pidof csm)` still works.

Or from the web UI: **Rules** page > **Reload Rules** button.

Remote rule updates are now signature-verified. Any configuration that enables `signatures.update_url` or `signatures.yara_forge.enabled` must also set `signatures.signing_key` to the 64-character hex-encoded Ed25519 public key that verifies the downloaded `.sig` files.
Remote update URLs must use HTTP or HTTPS and must not point at localhost, loopback, link-local, unspecified, or RFC1918 / ULA private addresses.

## YARA Forge Integration

CSM can automatically fetch curated YARA rules from [YARA Forge](https://github.com/YARAHQ/yara-forge), which aggregates and quality-tests rules from 40+ public sources including signature-base, Elastic, Malpedia, and ESET.

### Configuration

```yaml
signatures:
  signing_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  yara_forge:
    enabled: true
    tier: "core"              # core (5K rules, low FP), extended (10K), full (12K)
    update_interval: "168h"   # weekly
    download_url: "https://mirrors.pidginhost.com/csm/yara-forge/{version}/yara-forge-rules-{tier}.zip"
  disabled_rules:             # rule names to exclude from Forge downloads
    - SUSP_Example_Rule
```

The project operates the signed mirror shown above. A ready-to-use drop-in is shipped at `/usr/lib/csm/profiles/yara-forge.example.yaml`; copy or include it under `/etc/csm/conf.d/` to enable Forge without editing the main `csm.yaml`. The matching `signing_key` is the project Ed25519 public key (hex), published on the [release signing](release-signing.md) page.

`signing_key` must be a hex string for the Ed25519 public key that matches the private key used to sign the remote Forge artifact. It is not a PEM block and not a file path.

YARA Forge's upstream GitHub releases publish ZIP files, but not CSM detached signatures. CSM therefore requires `yara_forge.download_url` to point at a mirror you operate. The URL may contain `{tier}` and `{version}` placeholders. The detached signature must be available at the resolved ZIP URL plus `.sig`.

When the URL has a standalone `{version}` path segment, CSM first reads a plain-text `latest` pointer from that version directory's parent, for example `https://mirrors.pidginhost.com/csm/yara-forge/latest`. If the pointer is not published, CSM falls back to the upstream GitHub release tag. Mirror network errors and server errors fail the update instead of falling back, because GitHub may name a release the mirror has not signed yet. CSM accepts only short tag tokens from the pointer; the ZIP signature still gates installation.

If you do not have a signed update source yet, disable remote updates instead:

```yaml
signatures:
  signing_key: ""
  update_url: ""
  yara_forge:
    enabled: false
```

### Tiers

| Tier | Rules | Size | False Positive Risk |
|------|-------|------|-------------------|
| core | ~5,000 | 1.6 MB | Low (quality >= 70, score >= 65) |
| extended | ~10,500 | 3.3 MB | Medium |
| full | ~11,600 | 3.7 MB | Higher (includes score >= 40) |

### Update Flow

1. CSM resolves the latest YARA Forge version from the mirror pointer, falling back to GitHub only when no pointer is published
2. If different from the installed version, downloads the ZIP for the configured tier from `yara_forge.download_url` and its detached signature
3. Verifies the download against `signatures.signing_key`
4. Filters out any rules listed in `disabled_rules`
5. Compile-tests the rules with YARA-X before installing
6. Atomically replaces the previous Forge rules file
7. Reloads the YARA scanner

Custom rules in `malware.yar` are never overwritten by the Forge fetcher.

### Disabling Rules

If a Forge rule produces false positives, add its name to `disabled_rules` in the config and reload:

```yaml
signatures:
  disabled_rules:
    - SUSP_XOR_Encoded_URL
    - HKTL_Mimikatz_Strings
```

After editing, send SIGHUP or restart the daemon to apply.

## How Rules Avoid False Positives

Signature rules require **structural nesting**, not co-presence of strings. Two dangerous function calls appearing in the same file but in unrelated code paths won't trigger a rule. The call must directly wrap or chain with the other for a match.

**Realtime signature auto-quarantine** adds a safety gate: only `webshell` and `dropper` matches are eligible, and the file must be at least 512 bytes and either have Shannon entropy >= 5.5 or hex density > 20% plus an obfuscated-execution signal. Legitimate plugin code (well below 5.5 entropy) passes through; obfuscated malware (5.8+) is caught.

## Alert Rate Limiting

Default: 30 emails/hour (configurable via `max_per_hour`). **CRITICAL findings always get through** regardless of rate limit. Only lower-severity alerts are rate-limited.

## Suppressions

Create suppression rules to silence known false positives:

- From the **Findings** page: click the suppress button on any finding
- From the **Rules** page: manage suppression rules directly
- Via API: `POST /api/v1/suppressions`

To suppress email alerts for specific checks while keeping them visible in the web UI, use `disabled_checks` in your config:

```yaml
alerts:
  email:
    disabled_checks:
      - "email_spam_outbreak"
      - "perf_memory"
```
