# Signature Rules

CSM matches file content against signature rules. YAML rules run in real-time scanning and when CSM re-checks a finding. Optional YARA-X rules also run during deep scans and email attachment scanning. All rules are stored in `/opt/csm/rules/`.

If an engine loads zero rules, CSM raises a `realtime_rules_missing` finding at startup and after every reload. A mistyped `signatures.rules_dir` or an empty rule sync causes this. Without the finding, both engines would treat an empty directory as a successful load and scan every write against nothing.

## Updating Rules

```bash
csm update-rules          # download latest rules and reload the running daemon
```

When the download completes, `csm update-rules` asks the daemon to reload through the control socket. If the daemon is not running, the next start picks the files up automatically. `kill -HUP $(pidof csm)` also reloads the rules.

In the Web UI, open the Rules page and click the Reload Rules button.

### Signed updates

Remote rule updates are signature-verified. Any configuration that enables `signatures.update_url` or `signatures.yara_forge.enabled` must also set `signatures.signing_key`. The key is the 64-character hex-encoded Ed25519 public key that verifies the downloaded `.sig` files.

Remote update URLs have two rules:

- They must use https. A plain-http URL fails validation.
- They must not point at localhost, loopback, link-local, unspecified, or RFC1918 / ULA private addresses.

### Updates CSM refuses

A valid signature proves who published a rules file, not that it is the current one. So the YAML updater also refuses a download in two cases, and keeps the installed rules:

- The download's `version` is lower than the installed file's.
- The download carries fewer than half as many rules as the installed file.

The daemon emits a Critical finding for either refusal. A stale mirror or a replayed old release is then visible, and cannot silently strip detection.

CSM does not compare against an installed file that is missing or cannot be parsed. A signed update therefore remains the way to recover from a corrupt rules file.

### Reducing the rule count on purpose

For an intentional reduction below half the installed YAML rule count:

1. Set `signatures.allow_rule_count_decrease: true` and restart CSM.
2. Run the signed update.
3. Return the setting to `false` and restart CSM again.

This exception never permits a version downgrade.

## Disabling Rules

If a rule produces false positives, add its name to `disabled_rules` in the config and restart the daemon:

```yaml
signatures:
  disabled_rules:
    - SUSP_XOR_Encoded_URL
    - php_goto_obfuscation
```

Disabling a rule is a last resort and a standing gap in coverage. Prefer fixing the rule.

The list covers every rule CSM loads, not only YARA Forge:

- Forge rules are stripped from the download.
- Rules shipped in `malware.yml` are skipped when the real-time engine loads them.
- Rules shipped in `malware.yar` are stripped before the scheduled engine compiles them.

The [self-test](self-test.md) measures the ruleset that is left, so disabling a rule shows up as the coverage it costs.

### How names match

Names are matched in full, ignoring surrounding whitespace and letter case. Prefixes and substrings do not match.

`csm validate` warns about a name that matches no rule. Without the warning, a typo reads as "that rule is off" while the rule keeps firing. Validation recognizes a disabled YAML rule even if its regular expression is invalid, and counts repeated names only once.

### When the list takes effect

Signature settings require a daemon restart. SIGHUP does not apply a changed disabled list, and rule-file reloads keep the current list.

The daemon strips disabled rules before every compile, so rule reloads and worker restarts keep honoring the list. Removing a YARA rule preserves neighboring rules, including when declarations share a line or literals contain braces.

### Disabling every rule

A valid ruleset whose rules are all disabled loads as an empty set, including on reload. Stale rules are not retained. The self-test reports the resulting misses. An empty or invalid replacement still reports a load error.

## Suppressions

A suppression rule silences a known false positive. You can create one in four ways:

- On the Findings page, click the suppress button on any finding. The path pattern is a glob. The dialog pre-fills the finding's own file with `[`, `]`, `*`, `?` and `\` escaped, so the rule matches that file only.
- On the Findings page with several findings selected, bulk Suppress creates one rule per selected file.
- On the Rules page, manage suppression rules directly.
- Through the API, call `POST /api/v1/suppressions`.

### What a suppression stops

| A suppression rule stops | It does not stop |
|--------------------------|------------------|
| Showing matching findings on the Findings page | IP blocking |
| Email and webhook alerts for them | Challenge routing |
| File, process and account remediation for them | Attack scoring |

The right column stays active because a rule that mutes a whole check would otherwise leave every attacker that check reports unblocked. To exempt an address that was blocked by mistake, whitelist it on the Firewall page under Allow Rules or with `csm firewall allow`.

These points also hold:

- Incident auto-blocking, credential-spray containment and central threat intelligence also use suppressed findings.
- Database response never blocks session IPs. A suppressed database finding cannot trigger cleanup or session revocation.
- IP action notifications are separate findings. Suppressing their check type mutes those notifications without stopping the action.

These rules apply to startup, scheduled and real-time scans, control-socket runs with alerts enabled, and replay after restart.

### Muting email for a check

To suppress email alerts for specific checks while keeping them visible in the Web UI, use `disabled_checks` in your config:

```yaml
alerts:
  email:
    disabled_checks:
      - "email_spam_outbreak"
      - "perf_memory"
```

## YAML Rules

A YAML rule lists the text a file must contain to match:

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

### Fields

| Field | Meaning |
|-------|---------|
| `name` | Unique rule identifier. |
| `severity` | critical, high, or warning. |
| `category` | webshell, backdoor, phishing, dropper, exploit. |
| `file_types` | File extensions to match, or `["*"]` for all. |
| `patterns` | Case-insensitive literal strings. |
| `regexes` | Regex patterns, compiled case-insensitively. |
| `regex_pairs` | Entries with `first`, `second` and `max_distance`. Each pair counts as one regex match when its match starts are within that many bytes, in either order. |
| `exclude_patterns` | Literal patterns that suppress a match (false positive reduction). |
| `exclude_regexes` | Regex patterns that suppress a match. |
| `min_match` | Minimum total number of matching literal and regex entries. Each entry counts once. |
| `require_regex` | Require at least one regex among the matches counted toward `min_match`. |
| `max_file_bytes` | Skip this rule when the complete scanned file is larger than the byte limit. Omitted or `0` is unbounded. |
| `max_file_bytes_exempt_regexes` | High-confidence regexes that let the rule continue normal evaluation above `max_file_bytes`. |

### Writing regexes that scan fast

A regex only runs on a file that contains the fixed text every match of it must contain. The comparison ignores case. For `eval\s*\(\s*base64_decode` the fixed text is both `eval` and `base64_decode`.

Write regexes around distinctive words such as function names. A regex with no fixed text of two or more characters runs over every file of its types, and realtime pays that cost on each write.

Required text can include escaped bytes such as `\x00`. These remain part of the literal when CSM checks whether a file could match.

### Regex pairs

Regex pairs compare the ordered, non-overlapping matches of two expressions.

- Both expressions must be non-empty and must compile.
- `max_distance` must be non-negative.
- A distance of zero requires both matches to start at the same byte.

Use pairs for nearby evidence. Do not join two expressions with a wide wildcard gap, which can slow finding re-checks on large files.

### Counting independent evidence

When a regex includes a literal listed in `patterns`, the same content can satisfy both entries. Use independent entries when a rule needs multiple pieces of evidence. The bundled HTTP tunnel rule, for example, requires both socket creation and a CONNECT request. Generated socket wrappers stay silent under that rule.

[Notes on bundled signatures](#notes-on-bundled-signatures) describes the evidence that some bundled rules need.

## YARA-X Rules (Optional)

Build CSM with YARA-X support:

```bash
CGO_LDFLAGS="$(pkg-config --libs --static yara_x_capi)" go build -tags yara ./cmd/csm/
```

Without the `yara` build tag, YARA rules are not loaded or evaluated, and the worker backend reports files as not scanned.

Place `.yar` or `.yara` files alongside YAML rules in `/opt/csm/rules/`. CSM compiles them at startup and uses them for:

- Real-time fanotify file scanning
- Scheduled deep-scan filesystem sweeps
- Email attachment scanning

### Ownership and permissions

The rules directory and rule files must be owned by root or the scanner user and must not be group- or world-writable. The installer uses `0750` for the directory and `0640` for shipped rules. Custom rules must also remain readable by the service.

The standard service runs as root and reads the rule files. The YARA workers get the rule text from the service and never open the files. With the default worker enabled, rule files cannot include other files.

### What scheduled sweeps scan

Scheduled YARA sweeps scan regular, non-empty files under the configured `account_roots`. When no override is configured they scan the cPanel `/home/*/public_html` roots. They skip files larger than `thresholds.full_scan_max_file_mb`, symlinks and special files.

Scheduled findings and real-time fanotify findings have separate ownership, so one path cannot purge the other's results.

### When a scan cannot finish

| Case | Finding |
|------|---------|
| A scheduled sweep meets an unreadable or oversized file, or a scanner backend error | `yara_scan_incomplete`. CSM preserves the findings from the previous complete sweep. |
| A real-time scan cannot inspect a changed file | `yara_realtime_scan_error` |

The two findings keep a scanning outage separable from the scheduled coverage report. The dashboard's Components matrix shows `yara_realtime_scan_error` as Fanotify's last event. Scheduled coverage reports do not advance that event time.

CSM suppresses `yara_realtime_scan_error` while the file monitor is stopping. The YARA backend stops before the file monitor has finished draining, and a clean restart is not an outage.

[When the YARA worker reports a file as not scanned](#when-the-yara-worker-reports-a-file-as-not-scanned) covers rule loads and repeated worker failures.

## YARA Forge Integration

CSM can automatically fetch curated YARA rules from [YARA Forge](https://github.com/YARAHQ/yara-forge). YARA Forge aggregates and quality-tests rules from 40+ public sources, including signature-base, Elastic, Malpedia, and ESET.

### Configuration

```yaml
signatures:
  signing_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  yara_forge:
    enabled: true
    tier: "core"              # core (5K rules, low FP), extended (10K), full (12K)
    update_interval: "168h"   # weekly
    download_url: "https://mirrors.pidginhost.com/csm/yara-forge/{version}/yara-forge-rules-{tier}.zip"
  disabled_rules:             # rule names to switch off, in Forge and in the shipped rules
    - SUSP_Example_Rule
```

The project operates the signed mirror shown above. A ready-to-use drop-in is shipped at `/usr/lib/csm/profiles/yara-forge.example.yaml`. Copy or include it under `/etc/csm/conf.d/` to enable Forge without editing the main `csm.yaml`.

`signing_key` must be a hex string for the Ed25519 public key that matches the private key that signs the remote Forge artifact. It is not a PEM block and not a file path. For the project mirror, the matching key is the project Ed25519 public key (hex), published on the [release signing](release-signing.md) page.

If you do not have a signed update source yet, disable remote updates instead:

```yaml
signatures:
  signing_key: ""
  update_url: ""
  yara_forge:
    enabled: false
```

### The download mirror

YARA Forge's upstream GitHub releases publish ZIP files, but not CSM detached signatures. CSM therefore requires `yara_forge.download_url` to point at a signed mirror: the project mirror shown above, or one you operate.

- The URL may contain `{tier}` and `{version}` placeholders.
- The detached signature must be available at the resolved ZIP URL plus `.sig`.

When the URL has a standalone `{version}` path segment, CSM first reads a plain-text `latest` pointer from that version directory's parent, for example `https://mirrors.pidginhost.com/csm/yara-forge/latest`.

| Pointer result | What CSM does |
|----------------|---------------|
| The pointer is not published | Falls back to the upstream GitHub release tag. |
| A mirror network error or server error | Fails the update and does not fall back, because GitHub may name a release the mirror has not signed yet. |

CSM accepts only short tag tokens from the pointer. The ZIP signature still gates installation.

### Tiers

| Tier | Rules | Size | False Positive Risk |
|------|-------|------|-------------------|
| core | ~5,000 | 1.6 MB | Low (quality >= 70, score >= 65) |
| extended | ~10,500 | 3.3 MB | Medium |
| full | ~11,600 | 3.7 MB | Higher (includes score >= 40) |

### Update Flow

1. CSM resolves the latest YARA Forge version from the mirror pointer. It falls back to GitHub only when no pointer is published.
2. If the version differs from the installed one, CSM downloads the ZIP for the configured tier from `yara_forge.download_url`, and its detached signature.
3. CSM verifies the download against `signatures.signing_key`.
4. CSM filters out any rules listed in `disabled_rules`.
5. CSM compile-tests the rules with YARA-X before installing. With worker mode enabled, this happens in the compile unit.
6. CSM atomically replaces the previous Forge rules file.
7. CSM reloads the YARA scanner.

The Forge fetcher never overwrites custom rules in `malware.yar`.

## How Rules Avoid False Positives

Signature rules require structural nesting, not co-presence of strings. Two dangerous function calls that appear in the same file but in unrelated code paths do not trigger a rule. One call must directly wrap or chain with the other for a match.

YARA-X rules cannot express nesting, so multi-string rules state how their evidence is related:

- A bounded distance is used when closeness is part of the malicious shape.
- When valid malware can carry padding between its signals, PHP diagnostic records are kept as separate contexts, so one record cannot borrow evidence from another.
- Anchoring works the same way. A CGI webshell rule requires its shebang at offset 0, because that is where the web server needs it.

None of these controls refers to a file's name or path.

### Auto-quarantine safety gate

Realtime signature auto-quarantine adds a safety gate. A match is eligible only when all of these hold:

- The match category is `webshell` or `dropper`.
- The file is at least 512 bytes.
- The file has Shannon entropy >= 5.5, or it has hex density > 20% plus an obfuscated-execution signal.

Legitimate plugin code is well below 5.5 entropy and passes through. Obfuscated malware is at 5.8 or above and is caught.

## Alert Rate Limiting

By default CSM sends at most 30 operator alert dispatches an hour. Change the limit with `max_per_hour`.

| Findings | Treatment |
|----------|-----------|
| CRITICAL findings and threat-intel reputation sightings | Always get through by email or generic webhook regardless of the rate limit, and do not count against it. |
| Other lower-severity alerts | Rate-limited. |
| Summary-class findings | Never reach the cap. They go to the daily summary instead of email or the generic webhook. |

Lower-severity alerts are rate-limited even when they are batched with a CRITICAL finding. Once the budget is spent, only the urgent findings in that batch are sent.

Summary-class findings are attacks CSM already blocked or challenged, its applied block and challenge notices, and the other findings listed under Alert classes in the [configuration reference](configuration.md).

### What uses a slot

- A dispatch uses one slot only when email or a generic webhook successfully delivers routine findings.
- If only urgent findings reach a channel and routine delivery fails, the slot remains available for a later dispatch.
- Email-disabled findings do not reserve a slot unless a generic webhook will carry them.
- The phpanel webhook stream bypasses this budget.

## Details

This section is reference material. It covers what a scan reads, how the YARA worker reports files it could not scan, and what evidence each bundled signature needs. The last two parts are for developers who change the bundled rules.

### Rolling deep scans

Deep scans are rolling. Each scheduled run resumes from a persisted cursor and scans as much as fits in its time budget. The whole content set is covered across runs even when a single run cannot finish it. CSM raises a warning finding if no full pass has completed within 30 days.

The same rolling walk also feeds two analyzers: the JavaScript keystroke taint analyzer (`js_keylogger_dataflow`) and the PHP remote-source taint analyzer (`php_remote_taint`). See the [deep checks reference](detection-deep.md) for both.

Each consumer keeps its own cursor and completion record, so none of them stalls the others:

- A missing or failed YARA backend does not hold up either taint analyzer.
- An unavailable PHP analyzer does not affect YARA or JavaScript coverage.

### PHP file types

A rule declaring `file_types: [".php"]` is applied to every extension a stock PHP handler executes: `.php2` through `.php8`, `.phtml` and `.pht`. It is also applied to `.phps`, because that source-view extension still contains PHP source.

`.phps` stays outside the set of extensions CSM treats as executable. So this does not change which files the real-time dropper tracker considers runnable.

### Archives

Both engines skip ZIP, gzip, bzip2, xz, 7z, and RAR containers, but only when the file name carries an archive extension as well as the archive signature. Matching compressed bytes or stored filenames produces false positives without inspecting the archived file. Real containers are scanned when they are extracted onto monitored storage instead.

The skip has three limits:

- A file whose name a web server would execute is always scanned, whatever its first bytes look like. PHP echoes any leading bytes and runs the rest.
- Uncompressed tar files and executable PHP archives (PHAR) remain scannable.
- Filename-based phishing-kit archive detection is unchanged.

### When the YARA worker reports a file as not scanned

These rules apply with `signatures.yara_worker_enabled: true`, which is the default.

| Case | What CSM reports |
|------|------------------|
| No rule load has succeeded yet, including while a failed startup compile is retried | Files are reported as not scanned. |
| The rules directory is empty | It counts as loaded for files. Mail parts are reported as not scanned until at least one rule loads. |
| A reload fails | CSM keeps the rules already loaded. |
| The content of a file or mail part made the scan worker fail twice within a day | It is temporarily reported as not scanned without another attempt, including when copies are already queued. |

A successful rule load clears the recorded worker failures. They also expire a day after the last failure. The oldest failures may be forgotten earlier if many different inputs fail.

### Notes on bundled signatures

Each note says what evidence a bundled signature needs and what it leaves alone.

#### Encoded spam links

Encoded spam-link detection applies to real-time scanning and finding re-checks only. Scheduled YARA scans do not use this rule.

The rule looks for external-link attributes in PHP that directly prints a base64 literal. Embedded tracking pixels, local image references and inline logos without external links do not supply that evidence.

An encoded external link is a heuristic. It is not proof of spam, and not proof that the destination is outside the site's own domain.

#### WordPress REST API exploit

The WordPress REST API exploit signature is a YAML-only heuristic. It requires both of these:

- A users-endpoint URL literal.
- A password query parameter, or a nearby PHP, JSON or form-encoded password field. Payloads prepared before the URL count too.

Endpoint prose alone does not qualify. This is bounded textual evidence, not PHP data-flow analysis or proof that a request is unauthorized.

#### Legacy PHP callback

The legacy PHP callback rule uses the same narrow signature in YAML and YARA-X. It matches a direct function call with these two arguments:

- The first argument is a quoted parameter list, a variable, `null`, a simple array lookup or a short helper call.
- The second argument is a decoder or request lookup, optionally preceded by one concatenated literal.

The forms are bounded:

- Quoted lists can contain commas, semicolons and escaped quotes.
- Array indices accept a single quoted key or an unquoted scalar.
- Helper arguments accept at most one literal among unquoted scalar operands, including `implode(',', $args)`.
- Double-quoted array keys, helper literals and body prefixes must escape dollar signs. Unescaped dollars require interpolation analysis.

These bounded forms consume quoted operands whole and exclude comments, interpolation and nested expressions. Delimiters inside data therefore cannot supply the body-source evidence.

Shared positive and benign fixtures check both engines. Generated funchand wrappers and ordinary legacy callbacks stay silent under this rule. [Legacy callback parser follow-up](#legacy-callback-parser-follow-up) lists the cases this signature leaves out.

#### Cron downloader

The cron downloader signature shares its expression between both engines. It requires a download followed by a complete shell, eval or exec command on the same line. Quoted shells, command groups, common execution wrappers and shell lookup commands are recognized.

It recognizes these schedules:

- Numeric five-field schedules and the standard `@` shortcuts, including lists, range steps and randomized ranges.
- A single three-letter ASCII name, in either case, in the month and weekday fields.

It does not match these:

- Unicode lookalikes are not schedule names.
- Name lists and ranges are not matched, because they made crafted lines too costly to scan.

Schedule tokens must be complete and separated by spaces or tabs. Fields are limited to 64 characters.

Root entries that disable cron logging and scripts that install a quoted cron entry remain covered. Bounded spans keep crafted lines cheap to scan. Unrelated lines and shell words inside longer command names are not evidence.

#### Download-and-pipe, miner and shell startup file signatures

The download-and-pipe, miner download, miner cron and shell startup file signatures also look for their parts within bounded spans of one line, in both engines. A download command is found wherever it sits on a long line. A `#` shortly before it still marks a commented-out usage line.

Both engines report download-and-pipe commands even when a file begins with HTML or has an HTML extension. This includes install commands printed on web pages. Leading markup does not prove that later lines cannot run as shell code.

The YARA-X rules treat a command as documentation in only two places:

- Inside a fenced code block, whose opening fence starts a line and whose closing fence stands on its own line.
- As the text of a Markdown link.

A file with more Markdown blocks and links than any published document carries is the exception. The shell startup file signature judges it without that suppression, so its scan time stays linear.

The download-and-pipe and shell startup file signatures need a whole shell or interpreter name after the pipe. A download piped into a checksum tool, or into another program whose name starts the same way, is not an execution. Versioned Perl and Python names, Python build variants and standard Windows executable names retain detection. Both engines use the same shell name boundaries, including commands embedded in strings and binary data.

The miner cron signature has these rules:

- It ignores letter case in both engines.
- It accepts only spaces and tabs between schedule fields.
- It counts its bounded command span in characters, so non-ASCII paths have the same coverage.

The other bounded spans are measured in bytes by the YARA-X rules and in characters by the YAML rules. The two engines can therefore disagree on a line with non-ASCII text in the span. Measuring characters in YARA-X slowed scans of crafted lines too much. A finding is re-checked by the engine that raised it.

#### Unauthenticated uploader

The unauthenticated uploader signature skips a framework helper class. That is a file holding only a direct-access guard that exits and one class declaration, which writes the upload through the object and creates no object itself. Code after the class, or syntax the check cannot read, keeps the alert.

#### PHP goto obfuscation

The PHP goto-obfuscation rule requires three independent signals in both engines:

- A PHP opening tag.
- At least nine jumps to digit-bearing generated labels, or eleven to alphabetic labels.
- A decode call, execution call, dynamic include, or request input.

These rules decide what counts:

- Fixed-path bootstrap includes do not supply this evidence.
- Variable and array callback calls count even when the function name is constructed and the argument is a literal.
- Comments between a callable and its opening parenthesis do not hide the call.
- Line breaks and keyword case do not change the label counts.
- Long encoded strings and data URIs alone are not execution evidence.

These are source-text heuristics, not PHP dataflow analysis. They cannot resolve arbitrary dynamically generated code or distinguish every benign use of these operations.

The PHP content heuristic that runs during scans applies the same evidence rule. Generated goto labels and descriptive goto labels both need a decode call, execution call, dynamic include, or request input before they count as an obfuscation indicator. `call_user_func` is deliberately not evidence in either place, because plugin loaders dispatch their own callables through it.

The content heuristic uses the signature's evidence expression, including comment-separated calls, grouped and array callbacks, and case-sensitive PHP superglobal names. A regression check guards against expression drift.

#### Archive loader

The archive loader signature reports PHP that runs code read out of an archive, in both engines. It starts from a ZipArchive member read, or a `zip://` or `phar://` path. That read or path must do one of these:

- Sit inside an `eval`, `assert` or `create_function` call.
- Lie within 1000 bytes of an `eval` that leaves PHP mode first, before or after it. Both engines measure between match starts.
- Follow a password set on the archive and precede `eval` of a variable.

Including a `zip://` path is reported with or without parentheses.

These are not evidence:

- Extracting archives to disk, parsing data members, and template engines evaluating local text.
- A bundled tool such as a `.phar` whose stub names an archive path far from a template engine's `eval`.
- Assertions that parse or compare archive data.

These are source-text heuristics, not PHP dataflow analysis. Execution arguments stop at the end of their call while allowing balanced prefix calls. Both strings passed to `create_function` remain source text, as described in the [PHP manual](https://www.php.net/manual/en/function.create-function.php).

Regression fixtures run through both engines, including mixed-case calls and ordinary archive and template code.

#### WordPress injection kit

Three signatures report code an injection kit leaves in WordPress files, in both engines.

- The first-line stub signature matches only a file that opens with an array holding an empty string followed by an `isset` test with an empty body. The line does nothing, outlives cleaners that strip only the payload, and no generator writes it.
- The visitor logger signature needs a site or host hash, cookie handling, an append-mode `fopen` and a visitor address read. Each must start within 1200 bytes of a lookup of the upload temp directory.
- The hook injector signature needs `add_action` or `add_filter` called with a hook name returned by a call on an encoded literal, starting within 4096 bytes of both base64 decoding and a byte-wise XOR loop.

Plugins that name hooks in plain text, keep caches in the temp directory or mask license keys with XOR are not evidence.

#### PHP carried inside an image

Scans hand every file to YARA-X regardless of its name, so a rule may decide on the leading bytes rather than the extension. The bundled rule for PHP carried inside an image does that. A picture is a working payload store, and nothing about its name says so. The rule requires all of these:

- A genuine PNG, JPEG, GIF, WebP, ICO, BMP or TIFF container.
- A PHP opening tag.
- An execution or remote-fetch construct beside it.

The rule's other half is the loader: a PHP file that includes or requires a non-executable file while reading request input.

- The extension list covers images, archives and opaque data files.
- Source partials such as `.html`, `.tpl`, `.txt` and `.svg` are deliberately absent, because including those can be ordinary templating.
- Literal targets must end the include statement. An image named later in a rendered HTML expression is not an include target.
- Encoded targets remain suspicious regardless of the hidden extension.

Findings include up to five distinct non-executable path literals near an include or require. These are candidate payload references: proximity does not prove variable identity, and concatenated paths may be partial. Extraction advances through the content once and stops when the output cap is reached.

#### Native Linux droppers

Native Linux programs are judged by content too. CSM reports a program as a Critical dropper, wherever it sits, when it carries a `wget` or `curl` download command with an open output path together with either of these:

- A URL to a PHP script or `.htaccess` file, including at the URL root.
- PHP source that writes files.

The ELF header decides what counts as a program. Non-PIE, PIE and static PIE executables do. Shared libraries, such as native Node.js modules and Python extensions, do not. The executable bit is not consulted.

A program in a web root without those traits is not reported. Vendor download binaries, bundled build tools such as esbuild, image optimizer binaries and old CGI programs are normal there.

### Legacy callback parser follow-up

This part is for developers. The callback signature does not inspect quoted function bodies. Doing so needs PHP string decoding, tokenization and expression analysis. For example, `assert($x > 0)` is an ordinary boolean check, and `"eval($x)"` can be data.

The rules scan source text. They do not promise general PHP comment or string awareness, nor complete coverage of dynamically generated code.

The cases below are deliberately outside the narrowed signature. The expanded regex covered them. They remain acceptance cases for a parser follow-up, not claims of current detection by this rule:

| Deferred case | Examples to restore |
| --- | --- |
| Constructed parameter lists | Concatenation, nested array indices, helper calls with multiple quoted operands, and `chr(100/(1+1))` as the first argument; only the bounded simple forms above are covered |
| Comments inside constructed parameters | Comments in array indices or helper arguments, especially those containing closing delimiters or body-source names |
| Interpolated parameter operands | Double-quoted array keys or helper operands containing unescaped dollars, including interpolation with nested quoted keys |
| Comments between arguments | Block comments with embedded commas, and line comments before the body source |
| Constructed body expressions | Grouped concatenation, parenthesized decoders and `trim(base64_decode($payload))`; a single literal concatenated onto request input is covered |
| Interpolated bodies | A double-quoted body such as `"return {$_POST['code']};"`, or a concatenated double-quoted prefix containing unescaped dollars |
| Literal executable bodies | `eval($x)` or string-capable `assert($x)`, with statements, strings or comments before them; both outer quote styles and escaped quotes |
| Literal expression contexts | `return`, `or`, `do`, `case`, `include`, `include_once`, `require`, `require_once`, `clone`, `yield from`, comparisons, shifts and inequality before an execution sink |
| Literal lexical edges | Global `assert`, comment backslashes before `*` or `*/`, and quoted operands before a comparison |
| Outer call contexts | Calls immediately following a ternary colon, case-label colon or comparison operator |

This work belongs in `internal/phptaint`, which already uses VKCOM/php-parser and records the second argument of `create_function` as a sink. Extend that analysis to do three things:

- Decode and parse statically known callback bodies under its existing budgets.
- Distinguish boolean assertions from string execution.
- Report unresolved dynamic bodies as analysis gaps.

That analysis currently feeds a separate scheduled check. It is not a post-filter for YAML or YARA. Realtime coverage would need explicit integration and latency tests, and standalone YARA would still have the narrower coverage.

Acceptance requires all of these:

- Restoring the deferred cases as positive parser fixtures.
- Retaining the shared benign fixtures.
- Checking both quote styles and comment forms.
- Passing the clean-corpus gate without new baseline entries.

Do not expand another regex into a PHP tokenizer to recover these cases.

### Testing bundled rule changes

Before merging bundled YARA changes, run the rules against an unpacked corpus of clean WordPress core and plugin files:

```bash
YARA_FP_CORPUS=/path/to/corpus go test -tags yara ./internal/yara/ -run TestRepositoryRulesAgainstCleanCorpus -v
```

The same corpus measures the YAML rules that only realtime and finding re-check run:

```bash
YARA_FP_CORPUS=/path/to/corpus go test ./internal/signatures/ -run TestRepositoryYAMLRulesAgainstCleanCorpus -v
```

The same corpus also checks that no YAML regex is skipped on a file it matches:

```bash
YARA_FP_CORPUS=/path/to/corpus go test ./internal/signatures/ -run TestYAMLGatesSoundOnCleanCorpus -v
```

Both gates require at least 5,000 non-empty files within the default scheduled scan size limit. Rule-load, traversal, and read failures fail the relevant run and do not count as clean. YARA backend errors do too.

The measured YARA baseline is empty. The YAML baseline records rules that already fire on clean plugin and core code and are named in the realtime-rule porting backlog. Tighten a noisy rule rather than excluding paths or filenames.
