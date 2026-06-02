package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/pidginhost/csm/internal/firewall"
)

// WebUIToken is one entry in WebUI.Tokens. Scope must be "admin" or "read".
type WebUIToken struct {
	Name  string `yaml:"name"`
	Token string `yaml:"token"`
	Scope string `yaml:"scope"`
}

// DefaultMaxBlocksPerHour is the safe hourly cap used when the operator
// leaves auto_response.max_blocks_per_hour unset or sets it to 0.
const DefaultMaxBlocksPerHour = 50

// MailLogsConfig controls how postfix/dovecot logs are read.
//
//	source: auto    - try file first; fall back to journal if file absent.
//	source: file    - require log file at the platform-default path.
//	source: journal - read from systemd-journald (units must be set).
//
// Units is consulted for journal fallback: the daemon matches each
// systemd unit by name, appending ".service" for bare service names.
type MailLogsConfig struct {
	Source string   `yaml:"source"`          // auto | file | journal
	File   string   `yaml:"file,omitempty"`  // override platform default
	Units  []string `yaml:"units,omitempty"` // for journal source
}

type Config struct {
	ConfigFile string `yaml:"-"`
	ConfigDir  string `yaml:"-" hotreload:"restart"` // /etc/csm/conf.d (or operator override); empty means no drop-ins loaded

	Hostname string `yaml:"hostname" hotreload:"restart"`

	Alerts struct {
		Email struct {
			Enabled        bool     `yaml:"enabled"`
			To             []string `yaml:"to"`
			From           string   `yaml:"from"`
			SMTP           string   `yaml:"smtp"`
			DisabledChecks []string `yaml:"disabled_checks"`
		} `yaml:"email"`
		Webhook struct {
			Enabled bool   `yaml:"enabled"`
			URL     string `yaml:"url"`
			Type    string `yaml:"type"` // slack, discord, generic, phpanel

			// HMACSecret is the shared secret used to sign each request when
			// Type=="phpanel". Read from this field directly OR via HMACSecretEnv
			// (env wins, for secret hygiene).
			HMACSecret    string `yaml:"hmac_secret,omitempty"`
			HMACSecretEnv string `yaml:"hmac_secret_env,omitempty"`

			// PerFinding documents the expected phpanel delivery shape. Phpanel
			// webhooks always emit one signed POST per finding; other webhook
			// types keep the existing digest delivery.
			PerFinding bool `yaml:"per_finding,omitempty"`
		} `yaml:"webhook"`
		Heartbeat struct {
			Enabled bool   `yaml:"enabled"`
			URL     string `yaml:"url"`
		} `yaml:"heartbeat"`
		MaxPerHour int `yaml:"max_per_hour"`

		// AuditLog ships every (deduplicated) finding to one or more
		// SIEM-friendly destinations. Schema is stable: parsers can
		// pin on the v=1 contract. Both sub-blocks default off; the
		// alert pipeline behaves identically to before when neither
		// is enabled.
		AuditLog struct {
			File struct {
				Enabled bool   `yaml:"enabled"`
				Path    string `yaml:"path"` // default: /var/log/csm/audit.jsonl
			} `yaml:"file"`
			Syslog struct {
				Enabled   bool   `yaml:"enabled"`
				Network   string `yaml:"network"`  // udp | tcp | unix | unixgram | tls
				Address   string `yaml:"address"`  // host:port or filesystem path
				Facility  string `yaml:"facility"` // default: local0
				TLSCAFile string `yaml:"tls_ca"`   // optional CA cert for tls
			} `yaml:"syslog"`
		} `yaml:"audit_log"`
	} `yaml:"alerts" hotreload:"safe"`

	Integrity struct {
		BinaryHash string `yaml:"binary_hash"`
		ConfigHash string `yaml:"config_hash"`
		// ConfdHash covers the conf.d drop-in fragments merged on top of the
		// main config. Empty when no fragments exist, so configs without
		// conf.d stay byte-identical to their pre-existing baseline. Without
		// it an attacker with write access to conf.d could override any
		// setting (auto_response, block_ips, dry_run) without tripping
		// integrity verification.
		ConfdHash string `yaml:"confd_hash"`
		Immutable bool   `yaml:"immutable"`
	} `yaml:"integrity"`

	Thresholds struct {
		MailQueueWarn             int `yaml:"mail_queue_warn"`
		MailQueueCrit             int `yaml:"mail_queue_crit"`
		StateExpiryHours          int `yaml:"state_expiry_hours"`
		DeepScanIntervalMin       int `yaml:"deep_scan_interval_min"`
		WPCoreCheckIntervalMin    int `yaml:"wp_core_check_interval_min"`
		WebshellScanIntervalMin   int `yaml:"webshell_scan_interval_min"`
		FilesystemScanIntervalMin int `yaml:"filesystem_scan_interval_min"`
		MultiIPLoginThreshold     int `yaml:"multi_ip_login_threshold"`
		MultiIPLoginWindowMin     int `yaml:"multi_ip_login_window_min"`
		// CredStuffingDistinctAccounts is the number of distinct accounts a
		// single source IP must fail against inside the multi_ip_login window
		// to raise a credential_stuffing finding. This is the breadth signal
		// (one source, many accounts) that the count-based pam_bruteforce
		// detector does not catch. Default 5 when unset or <=0, matching the
		// always-on posture of the sibling multi_ip_login_threshold.
		CredStuffingDistinctAccounts int `yaml:"cred_stuffing_distinct_accounts"`
		PluginCheckIntervalMin       int `yaml:"plugin_check_interval_min"`
		BruteForceWindow             int `yaml:"brute_force_window"`

		// DomlogMaxFiles caps how many per-domain access logs the WP brute
		// force check scans per cycle. Sites are ranked by recent mtime so
		// the cap chops least-active domains. Default 500. Bump on hosts
		// with many active domains so late-alphabet sites are not skipped.
		DomlogMaxFiles int `yaml:"domlog_max_files"`

		// AccountScanMaxFiles caps how many account and mail-domain paths
		// account-scoped scanners iterate per cycle. This covers SSH keys,
		// cPanel API tokens, Dovecot shadow files, CMS DB scans, forwarders,
		// user crontabs, and account .config backdoor paths. Paths are
		// ranked by mtime desc so the cap chops least-active accounts.
		// Default 10000 covers typical cPanel hosts with no cap effect.
		// Raise on very large multi-tenant hosts where late-mtime accounts
		// get skipped.
		AccountScanMaxFiles int `yaml:"account_scan_max_files"`

		// CrontabBase64BlobMaxBytes caps a single base64 candidate before
		// decoding in MatchCrontabPatternsDeep. Default 16384 encoded
		// bytes (~12 KiB decoded) comfortably fits any realistic gsocket
		// or `base64 -d|bash` payload while bounding work on adversarial
		// input. Raise on hosts where csm_checks_crontab_base64_truncated_total
		// shows recurring truncation. Must be a multiple of 4: standard
		// base64 requires aligned input or the decode fails and the
		// candidate is silently skipped.
		CrontabBase64BlobMaxBytes int `yaml:"crontab_base64_blob_max_bytes"`

		// DomlogTailLines is how many trailing lines the WP brute force
		// check reads from each per-domain access log per cycle. Default
		// 500 covers roughly 10 minutes of traffic on a busy site. Raise
		// on hosts where slow-burn attacks against high-volume domains
		// spread across more than 500 lines per scan interval, so the
		// per-IP counter window is wide enough to trip a threshold.
		DomlogTailLines int `yaml:"domlog_tail_lines"`

		// DomlogMaxAgeMin is how many minutes back the WP brute force
		// scanner accepts a per-domain access log as "fresh enough to
		// scan." Logs whose mtime is older than this are skipped. Default
		// 30 keeps the scan focused on currently-active vhosts. Raise on
		// low-traffic hosts where a slow-burn dictionary attack against
		// a quiet domain still needs to fall inside the window.
		DomlogMaxAgeMin int `yaml:"domlog_max_age_min"`

		// MailLogTailLines is how many trailing lines CheckMailPerAccount
		// reads from /var/log/exim_mainlog per cycle. Default 500. Raise
		// on busy mail hosts where a single account's spam burst spreads
		// across more than 500 lines per cycle.
		MailLogTailLines int `yaml:"mail_log_tail_lines"`

		// SyslogMessagesTailLines is how many trailing lines CheckFTPLogins
		// reads from /var/log/messages per cycle. Default 200. Raise on
		// hosts that share /var/log/messages with noisy services (e.g.
		// systemd-resolved chatter) so pure-ftpd failure lines do not
		// fall outside the window.
		SyslogMessagesTailLines int `yaml:"syslog_messages_tail_lines"`

		SMTPBruteForceThreshold    int `yaml:"smtp_bruteforce_threshold"`
		SMTPBruteForceWindowMin    int `yaml:"smtp_bruteforce_window_min"`
		SMTPBruteForceSuppressMin  int `yaml:"smtp_bruteforce_suppress_min"`
		SMTPBruteForceSubnetThresh int `yaml:"smtp_bruteforce_subnet_threshold"`
		SMTPAccountSprayThreshold  int `yaml:"smtp_account_spray_threshold"`
		SMTPBruteForceMaxTracked   int `yaml:"smtp_bruteforce_max_tracked"`

		// SMTP probe abuse counts raw inbound SMTP connect events per source
		// IP (independent of AUTH outcome) so probe-and-disconnect scanners
		// that never reach the AUTH stage are still caught. Threshold sized
		// well above any legitimate MUA usage. Explicit 0 disables.
		SMTPProbeThreshold   int `yaml:"smtp_probe_threshold"`
		SMTPProbeWindowMin   int `yaml:"smtp_probe_window_min"`
		SMTPProbeSuppressMin int `yaml:"smtp_probe_suppress_min"`
		SMTPProbeMaxTracked  int `yaml:"smtp_probe_max_tracked"`

		MailBruteForceThreshold    int `yaml:"mail_bruteforce_threshold"`
		MailBruteForceWindowMin    int `yaml:"mail_bruteforce_window_min"`
		MailBruteForceSuppressMin  int `yaml:"mail_bruteforce_suppress_min"`
		MailBruteForceSubnetThresh int `yaml:"mail_bruteforce_subnet_threshold"`
		MailAccountSprayThreshold  int `yaml:"mail_account_spray_threshold"`
		MailBruteForceMaxTracked   int `yaml:"mail_bruteforce_max_tracked"`

		// MailBruteAccountKey selects how the account is extracted from a
		// dovecot/postfix log line for per-account brute-force scoring.
		//   - builtin:dovecot-user (default) - match `user=<...>`
		//   - builtin:postfix-sasl           - match `sasl_username=<...>`
		//   - regex:<pattern>                - capture group 1 is the account
		MailBruteAccountKey string `yaml:"mail_brute_account_key,omitempty"`

		// ModSecEscalationHits is the number of ModSecurity denies from a
		// single source IP, inside ModSecEscalationWindowMin, that
		// promote the IP from "logged" to "escalated" (Critical finding
		// + firewall hand-off). Default 3. Lower it on hosts where
		// low-and-slow scanners go below the floor for too long.
		ModSecEscalationHits int `yaml:"modsec_escalation_hits"`
		// ModSecEscalationWindowMin is the sliding-window size for the
		// hit counter. Default 10. Bumping it (e.g. to 60-240) catches
		// paced attackers that spread denies across hours without
		// changing the trip count.
		ModSecEscalationWindowMin int `yaml:"modsec_escalation_window_min"`

		// HTTPFloodThreshold is the minimum requests per http_flood_window_min
		// from one source IP that emits http_request_flood. 0 (default) disables
		// the detector. Operators should sample baseline traffic before setting
		// a nonzero value.
		HTTPFloodThreshold int `yaml:"http_flood_threshold"`
		// HTTPFloodWindowMin is the rate window in minutes for HTTPFloodThreshold
		// counting. Default 5.
		HTTPFloodWindowMin int `yaml:"http_flood_window_min"`

		// HTTPUASpoofThreshold is the minimum per-IP per-window count
		// of WPSpoofPingback, ScriptingLang, Headless, or Empty UA
		// requests that emits http_ua_spoof. KnownScanner and
		// cache-confirmed negative ClaimedBot emit on count=1.
		// Default 30.
		HTTPUASpoofThreshold int `yaml:"http_ua_spoof_threshold"`

		// HTTPDistributedMinIPs is the number of distinct source IPs that
		// must each trip an HTTP-abuse threshold (wp-login / xmlrpc / user
		// enumeration / request flood / UA spoof) against one vhost in a
		// scan window before a single http_distributed_flood finding is
		// emitted for that vhost. Only already-abusive IPs are counted, so
		// a popular site's ordinary visitor spread does not trip it. 0
		// disables the detector; the shipped sample sets 10.
		HTTPDistributedMinIPs int `yaml:"http_distributed_min_ips"`

		// HTTPUAScriptingEnabled opts in to flagging scripting-language
		// UA strings (curl, python-requests, wget, etc.) as spoof candidates.
		// Off by default: many legitimate API integrations use these.
		HTTPUAScriptingEnabled bool `yaml:"http_ua_scripting_enabled"`
		// HTTPUAHeadlessEnabled opts in to flagging headless-browser UA
		// strings (HeadlessChrome, PhantomJS, Playwright, etc.). Off by
		// default: headless browsers are used by legitimate monitoring tools.
		HTTPUAHeadlessEnabled bool `yaml:"http_ua_headless_enabled"`
		// HTTPUAEmptyEnabled opts in to flagging requests with an empty or
		// dash User-Agent. Off by default: some CDN health checks omit UA.
		HTTPUAEmptyEnabled bool `yaml:"http_ua_empty_enabled"`
	} `yaml:"thresholds" hotreload:"safe"`

	InfraIPs []string `yaml:"infra_ips" hotreload:"restart"`

	StatePath string `yaml:"state_path" hotreload:"restart"`

	// Detection groups operator-facing knobs that gate detection
	// scanners. Today this is just the DB persistence-mechanism
	// scanner; future detection toggles land here.
	Detection struct {
		// DBObjectScanning toggles the MySQL persistence scanner
		// (triggers/events/procedures/functions). Tri-state *bool
		// matching the existing yara_worker_enabled pattern: nil =
		// default-on, *true = explicit on, *false = explicit off.
		// When off both the Critical (db_malicious_*) and Warning
		// (db_unexpected_*) emit paths fall silent; the manual
		// `csm db-clean drop-object` CLI keeps working so operators
		// can act on objects discovered by other means.
		DBObjectScanning *bool `yaml:"db_object_scanning"`

		// DBObjectAllowlist suppresses the Warning tier
		// (db_unexpected_*) for objects an operator has reviewed and
		// accepted. Entries shaped <account>:<schema>:<type>:<name>.
		// The Critical tier (db_malicious_*) ignores this list --
		// pattern hits always fire.
		DBObjectAllowlist []string `yaml:"db_object_allowlist"`

		// AdminOverlapMinAccounts is the threshold at which the
		// cross-account admin email correlator emits a finding. Default
		// 2 matches the most common compromise pattern on shared hosting
		// -- a contractor account used across multiple customer cPanels
		// is a single credential leak away from compromising every site
		// they touch. Operators with deliberately shared internal admin
		// emails (e.g. one ops team across many sites) can raise the
		// threshold to silence the routine overlap.
		AdminOverlapMinAccounts int `yaml:"admin_overlap_min_accounts"`
		// AdminOverlapTrustedEmails suppresses cross-account admin
		// overlap findings for exact, operator-reviewed email addresses.
		AdminOverlapTrustedEmails []string `yaml:"admin_overlap_trusted_emails"`
		// AdminOverlapTrustedDomains suppresses cross-account admin
		// overlap findings for exact email domains used by trusted
		// developer or reseller admin accounts.
		AdminOverlapTrustedDomains []string `yaml:"admin_overlap_trusted_domains"`

		// RescanOnSignatureUpdate fires a forced full-tree deep
		// scan the next time any file under cfg.Signatures.RulesDir
		// has its mtime advance. Tri-state *bool: nil = default-on,
		// *true = explicit on, *false = explicit off. Off means the
		// existing behaviour (deep-tier runs against the fanotify
		// short-list when fanotify is active) is unchanged; new
		// rules only catch files that change after the update.
		RescanOnSignatureUpdate *bool `yaml:"rescan_on_signature_update"`

		// AFAlgBackend selects the live AF_ALG (CVE-2026-31431, "Copy
		// Fail") detection backend. Empty / "auto" picks BPF LSM if
		// the binary was built with -tags bpf and the kernel supports
		// it, otherwise the audit-log inotify listener. "bpf" forces
		// BPF and disables the audit fallback (no live monitor if BPF
		// is unavailable; the periodic critical-tier check still
		// runs). "auditd" forces the audit listener even on BPF-
		// capable kernels -- a kill switch when a BPF-tagged release
		// misbehaves and the operator wants to revert without
		// rebuilding. "none" disables the live monitor entirely.
		AFAlgBackend string `yaml:"af_alg_backend"`

		// ConnectionTrackerBackend selects the live outbound-connection
		// tracker. Empty / "auto" tries BPF cgroup/connect4,6 first and
		// falls back to the existing /proc/net/tcp polling. "bpf"
		// requires BPF (no fallback). "legacy" pins polling. "none"
		// disables the live tracker; the periodic check still runs.
		ConnectionTrackerBackend string `yaml:"connection_tracker_backend"`

		// ConnectionPollInterval is how often the legacy polling backend
		// reads /proc/net/tcp(6). Ignored when the BPF backend is active.
		// Empty / zero defaults to 30s.
		ConnectionPollInterval time.Duration `yaml:"connection_poll_interval"`

		// ExecMonitorBackend selects the live process-exec monitor.
		// Empty / "auto" tries the sched_process_exec BPF tracepoint and
		// falls back to the periodic /proc walk. "bpf" requires BPF
		// (no fallback). "legacy" pins polling. "none" disables the live
		// monitor; the periodic deep-tier checks still run.
		ExecMonitorBackend string `yaml:"exec_monitor_backend"`

		// ExecMonitorPollInterval is how often the legacy polling backend
		// runs CheckSuspiciousProcesses + CheckFakeKernelThreads. Ignored
		// when the BPF backend is active. Empty / zero defaults to 30m.
		ExecMonitorPollInterval time.Duration `yaml:"exec_monitor_poll_interval"`

		// SensitiveFilesBackend selects the live sensitive-file write
		// monitor. Empty / "auto" tries the BPF LSM hook on /etc/shadow
		// and friends, falling back to a periodic content-hash check.
		// "bpf" requires BPF (no fallback). "legacy" pins polling.
		// "none" disables the live monitor; the periodic check still runs.
		SensitiveFilesBackend string `yaml:"sensitive_files_backend"`

		// SensitiveFilesPollInterval is how often the BPF watchset map
		// refreshes (to pick up newly-created files in glob directories
		// and handle inode reuse) and how often the legacy polling
		// backend runs the content-hash check. Empty / zero defaults to 5m.
		SensitiveFilesPollInterval time.Duration `yaml:"sensitive_files_poll_interval"`

		// DirectSMTPEgress flags non-MTA local processes opening
		// outbound SMTP connections. Phase 3 of the BPF Incident
		// Response Roadmap. Detection-only this phase; Phase 4 will
		// add the auto-response action gated by DryRun.
		DirectSMTPEgress struct {
			Enabled bool   `yaml:"enabled"`
			Backend string `yaml:"backend"` // auto / bpf / legacy / none
			// DryRun, when true (or absent for safety), reports findings
			// but takes no detector-scoped action. Phase 3 emits findings
			// regardless; the knob exists for the Phase 4 action.
			DryRun *bool `yaml:"dry_run,omitempty"`
			Ports  []int `yaml:"ports,omitempty"`
		} `yaml:"direct_smtp_egress" hotreload:"safe"`

		// BadASNOutbound flags outbound connections whose destination IP
		// resolves (via the GeoLite2-ASN database) to a bad or unexpected
		// autonomous system. It is the third leg of the host-takeover
		// chain correlator (alongside a new uid-0 account and a planted
		// suid binary). Requires the GeoLite2-ASN database. Off by default;
		// classification needs operator-supplied ASN lists.
		BadASNOutbound struct {
			Enabled bool `yaml:"enabled"`
			// BlockedASNs are autonomous system numbers always treated as
			// bad (e.g. known bulletproof hosters).
			BlockedASNs []uint `yaml:"blocked_asns"`
			// AllowedASNs, when non-empty, switches to allowlist mode: any
			// destination ASN outside this set is treated as bad. Use on
			// hosts whose legitimate egress is confined to a few providers.
			AllowedASNs []uint `yaml:"allowed_asns"`
		} `yaml:"bad_asn_outbound" hotreload:"safe"`
	} `yaml:"detection" hotreload:"safe"`

	Suppressions struct {
		UPCPWindowStart       string   `yaml:"upcp_window_start"`
		UPCPWindowEnd         string   `yaml:"upcp_window_end"`
		KnownAPITokens        []string `yaml:"known_api_tokens"`
		IgnorePaths           []string `yaml:"ignore_paths"`
		SuppressWebmail       bool     `yaml:"suppress_webmail_alerts"`      // don't alert on webmail logins
		SuppressCpanelLogin   bool     `yaml:"suppress_cpanel_login_alerts"` // don't alert on cPanel direct logins
		SuppressBlockedAlerts bool     `yaml:"suppress_blocked_alerts"`      // don't alert on IPs that were auto-blocked
		TrustedCountries      []string `yaml:"trusted_countries"`            // ISO 3166-1 alpha-2 codes - suppress cPanel login alerts from these countries
	} `yaml:"suppressions" hotreload:"safe"`

	AutoResponse struct {
		Enabled            bool   `yaml:"enabled"`
		KillProcesses      bool   `yaml:"kill_processes"`
		QuarantineFiles    bool   `yaml:"quarantine_files"`
		BlockIPs           bool   `yaml:"block_ips"`
		BlockExpiry        string `yaml:"block_expiry"`        // e.g. "24h", "12h"
		EnforcePermissions bool   `yaml:"enforce_permissions"` // auto-chmod 644 world/group-writable PHP files (default false)
		BlockCpanelLogins  bool   `yaml:"block_cpanel_logins"` // block IPs on cPanel/webmail login alerts (default false)
		NetBlock           bool   `yaml:"netblock"`            // auto-block IPv4 /24 or IPv6 /64 at threshold
		NetBlockThreshold  int    `yaml:"netblock_threshold"`  // IPs from same IPv4 /24 or IPv6 /64 before subnet block (default 3)
		// MaxBlocksPerHour caps per-IP auto-blocks per wall-clock hour.
		// 0 uses DefaultMaxBlocksPerHour.
		MaxBlocksPerHour    int    `yaml:"max_blocks_per_hour"`
		PermBlock           bool   `yaml:"permblock"`              // auto-promote to permanent after N temp blocks
		PermBlockCount      int    `yaml:"permblock_count"`        // temp blocks before permanent (default 4)
		PermBlockInterval   string `yaml:"permblock_interval"`     // window for counting temp blocks (default "24h")
		CleanDatabase       bool   `yaml:"clean_database"`         // auto-clean malicious DB injections, revoke sessions, block attacker IPs (default false)
		CleanHtaccess       bool   `yaml:"clean_htaccess"`         // auto-clean .htaccess directives flagged by the hardened detectors (default false)
		DisableEnforceAFAlg bool   `yaml:"disable_enforce_af_alg"` // suspend periodic AF_ALG enforcement; marker file + detection remain active (default false = enforce when marker present)
		CopyFailKillProcess bool   `yaml:"copy_fail_kill_process"` // SIGKILL processes caught opening AF_ALG sockets via the live listener (default false; alert-only)

		// DryRun, when true (or absent - safety default), logs the intended
		// action but does NOT touch nftables. Mirrors the PHPRelay.DryRun
		// pattern: pointer-bool to distinguish "operator explicitly set false"
		// from "operator omitted the key". Implicit nil means dry-run on, so
		// flipping block_ips: true alone never causes a real block.
		DryRun *bool `yaml:"dry_run,omitempty"`

		// PHPRelay controls the auto-freeze behaviour that companion
		// email PHP-relay detectors emit findings for. Freeze and DryRun
		// are *bool so we can distinguish OMITTED from EXPLICIT FALSE in
		// YAML. A plain bool zero-value is false, which would let an
		// operator write `freeze: true` and (by forgetting `dry_run`)
		// get LIVE freezes against their will. Pointer values: nil =
		// "not set in YAML"; *true / *false = explicit. Use the
		// FreezeEnabled() / DryRunEnabled() accessors on *Config to
		// resolve the safe defaults rather than dereferencing directly.
		PHPRelay struct {
			Freeze              *bool `yaml:"freeze"`
			DryRun              *bool `yaml:"dry_run"`
			MaxActionsPerMinute int   `yaml:"max_actions_per_minute"`
		} `yaml:"php_relay"`

		// VerdictCallback lets phpanel observe each block decision before it's
		// applied. CSM POSTs the verdict to the configured URL with HMAC-SHA256
		// signing (same scheme as the phpanel webhook); the response is
		// advisory - phpanel can attach a tenant_id, return "allow" to keep
		// the event audit-only, or omit a response entirely
		// (CSM proceeds with its default verdict). NOT a per-tenant nftables
		// enforcement: that's a separate, larger feature.
		//
		// Secret resolution happens at call time (the verdict.Client reads
		// HMACSecretEnv per call), so operators can rotate via env without
		// restarting the daemon.
		VerdictCallback struct {
			Enabled       bool   `yaml:"enabled"`
			URL           string `yaml:"url"`
			HMACSecret    string `yaml:"hmac_secret,omitempty"`
			HMACSecretEnv string `yaml:"hmac_secret_env,omitempty"`
			TimeoutSec    int    `yaml:"timeout_sec"`
			// RequireResponseSignature controls whether the panel must sign
			// its response body with the same HMAC scheme used on the
			// request (X-CSM-Signature header). Default true: when a secret
			// is configured, CSM rejects unsigned or forged responses to
			// prevent an on-path attacker from downgrading block to allow.
			// Set false only during a phpanel rollout that has not yet
			// implemented response signing. In that mode, CSM still checks
			// nonce or timestamp fields the panel echoes; responses that
			// omit both keep the legacy advisory shape working.
			RequireResponseSignature *bool `yaml:"require_response_signature,omitempty"`
			// AllowUnsigned opts out of the default fail-closed posture and
			// permits the verdict callback to fire without an HMAC secret,
			// including advisory "allow" responses. Only set true while
			// bootstrapping a new panel or during local testing; production
			// deployments must keep this false so the daemon refuses to start
			// when the secret env var is empty.
			AllowUnsigned bool `yaml:"allow_unsigned,omitempty"`
		} `yaml:"verdict_callback"`
	} `yaml:"auto_response" hotreload:"safe"`

	// BPFEnforcement is the optional in-kernel deny path for matched
	// outbound connections. Phase 4 of the BPF Incident Response
	// Roadmap. Defaults are all-safe: enforcement off, dry-run on.
	// Operators flip live denial only after dry-run telemetry review.
	BPFEnforcement struct {
		Enabled bool `yaml:"enabled"`
		// DryRun, when true (or absent for safety), logs intended
		// denials but allows the connect. False = real deny.
		DryRun           *bool `yaml:"dry_run,omitempty"`
		DirectSMTPEgress bool  `yaml:"direct_smtp_egress"`
		// VerdictCallback, when true, asks auto_response.verdict_callback
		// for an advisory ALLOW override before recording a USERSPACE
		// action (incident close, audit note). The in-kernel hook NEVER
		// waits on this; it would add latency to every connect.
		VerdictCallback bool `yaml:"verdict_callback"`
	} `yaml:"bpf_enforcement" hotreload:"safe"`

	Challenge struct {
		Enabled    bool   `yaml:"enabled"`     // enable challenge pages instead of hard block for some IPs
		ListenAddr string `yaml:"listen_addr"` // bind address for the challenge listener (default: 127.0.0.1)
		ListenPort int    `yaml:"listen_port"` // port for challenge server (default: 8439)
		// ListenAddr defaults to loopback because the production path
		// keeps the listener private until an operator deliberately
		// exposes it. The webserver integration redirects browsers to
		// challenge.public_url, so installed direct mode needs a
		// non-loopback listen address plus TLS material via
		// challenge.tls_cert / tls_key, or the webui TLS fallback.
		Secret         string   `yaml:"secret"`          // HMAC secret for challenge tokens (auto-generated if empty)
		Difficulty     int      `yaml:"difficulty"`      // proof-of-work difficulty 0-5 (default: 2)
		TrustedProxies []string `yaml:"trusted_proxies"` // IPs allowed to set X-Forwarded-For (empty = trust RemoteAddr only)
		// TLSCert / TLSKey activate HTTPS on the challenge listener. Empty
		// values keep loopback listeners on plain HTTP. Direct/public
		// listeners fall back to webui.tls_cert / webui.tls_key so
		// single-cert hosts can opt in without duplicating paths.
		TLSCert string `yaml:"tls_cert"`
		TLSKey  string `yaml:"tls_key"`
		// PublicURL is the external URL the webserver redirect target
		// points at. Operators put it on an existing TLS-valid host so
		// the integration does not need a new DNS record or cert.
		// Example: https://server.example.com:8439/challenge with
		// listen_addr=0.0.0.0, tls_cert/tls_key set to the host's
		// cpanel cert.
		// When empty the webserver-integration installer refuses to
		// run; per-vhost reverse-proxy is no longer supported because
		// LSWS proxy emulation does not honor it at server scope.
		PublicURL string `yaml:"public_url"`

		// CaptchaFallback shows a third-party CAPTCHA widget when JS is
		// disabled. All fields default empty; the feature is off until
		// the operator supplies provider + keys.
		CaptchaFallback struct {
			Provider  string        `yaml:"provider"`   // "turnstile" | "hcaptcha" | "" (off)
			SiteKey   string        `yaml:"site_key"`   // public key embedded in the HTML widget
			SecretKey string        `yaml:"secret_key"` // verified server-side against the provider
			Timeout   time.Duration `yaml:"timeout"`    // HTTP timeout for siteverify (default 10s)
		} `yaml:"captcha_fallback"`

		// VerifiedSession lets operators mint a signed cookie that
		// bypasses the PoW for the cookie's TTL. The signing key is
		// generated at daemon startup and rotates on restart.
		VerifiedSession struct {
			Enabled     bool          `yaml:"enabled"`
			CookieName  string        `yaml:"cookie_name"`  // default: csm_admin_session
			TTL         time.Duration `yaml:"ttl"`          // default: 4h
			AdminSecret string        `yaml:"admin_secret"` // shared secret POST'd to /challenge/admin-token
		} `yaml:"verified_session"`

		// VerifiedCrawlers allows-passes traffic from search crawlers
		// whose IP forward-confirms a reverse-DNS PTR matching one of
		// the configured providers.
		VerifiedCrawlers struct {
			Enabled   bool          `yaml:"enabled"`
			Providers []string      `yaml:"providers"` // names: googlebot | bingbot
			CacheTTL  time.Duration `yaml:"cache_ttl"` // default: 15m
		} `yaml:"verified_crawlers"`

		// PortGate locks the challenge listener TCP port to specific
		// source IPs via nftables. Enabled implies the daemon owns a
		// dedicated `csm_chal` inet table whose chain drops all traffic
		// to challenge.listen_port except: loopback, operator infra_ips,
		// and IPs the IPList has just flagged. The set entry carries
		// the same TTL as the challenge entry, so nftables expires the
		// allow even if the daemon dies before calling Revoke. Auto-off
		// when listen_addr is loopback (gate has no effect there).
		PortGate struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"port_gate"`
	} `yaml:"challenge" hotreload:"restart"`

	PHPShield struct {
		Enabled bool `yaml:"enabled"` // watch PHP Shield event log for alerts (default: false)
	} `yaml:"php_shield" hotreload:"restart"`

	Reputation struct {
		AbuseIPDBKey string   `yaml:"abuseipdb_key"`
		Whitelist    []string `yaml:"whitelist"` // IPs to never flag as malicious
		// Rspamd queries the local rspamd controller for per-IP reject/junk
		// counts. Disabled by default. URL must reach the controller HTTP port
		// (default 11334). Token is the controller's admin password (rspamadm
		// pw -e), supplied via env when possible. Token resolution happens at
		// query time so operators can rotate via env without daemon restart.
		Rspamd struct {
			Enabled  bool   `yaml:"enabled"`
			URL      string `yaml:"url"`
			Token    string `yaml:"token,omitempty"`
			TokenEnv string `yaml:"token_env,omitempty"`
		} `yaml:"rspamd"`
		// Upstream is an HTTP threat-intel source - typically a panel host that
		// caches AbuseIPDB / proprietary scores on behalf of every agent in its
		// fleet. Disabled by default. Token resolution happens at query time
		// (see internal/threatintel/upstream_source.go) so operators can rotate
		// the bearer via TokenEnv without restarting the daemon.
		Upstream struct {
			Enabled     bool   `yaml:"enabled"`
			URL         string `yaml:"url"`
			Token       string `yaml:"token,omitempty"` // discouraged - prefer TokenEnv
			TokenEnv    string `yaml:"token_env,omitempty"`
			CacheTTLMin int    `yaml:"cache_ttl_min"`
			TimeoutSec  int    `yaml:"timeout_sec"`
		} `yaml:"upstream"`
		// BotVerifyEnabled controls async PTR+forward-A verification of
		// claimed search-engine bot IPs. *bool so an explicit false
		// survives SIGHUP reload without being overwritten by applyDefaults.
		// Default true.
		BotVerifyEnabled *bool `yaml:"bot_verify_enabled"`
	} `yaml:"reputation" hotreload:"safe"`

	Signatures struct {
		RulesDir       string `yaml:"rules_dir"`
		UpdateURL      string `yaml:"update_url"`
		AutoUpdate     bool   `yaml:"auto_update"`     // auto-download rules daily (default: true if update_url set)
		UpdateInterval string `yaml:"update_interval"` // how often to check (default: "24h")
		SigningKey     string `yaml:"signing_key"`     // hex-encoded ed25519 public key for verifying rule updates
		YaraForge      struct {
			Enabled        bool   `yaml:"enabled"`
			Tier           string `yaml:"tier"`            // "core", "extended", "full" (default: "core")
			UpdateInterval string `yaml:"update_interval"` // default: "168h" (weekly)
			DownloadURL    string `yaml:"download_url"`    // signed ZIP URL/template; supports {tier} and {version}
		} `yaml:"yara_forge"`
		DisabledRules []string `yaml:"disabled_rules"` // YARA rule names to exclude from Forge downloads
		// YaraWorkerEnabled is a tri-state: nil means "use system default"
		// (default-on, per ROADMAP item 2 follow-up), *true means explicit on,
		// *false means explicit off. Callers must nil-check before dereferencing;
		// daemon.yaraWorkerOn() is the canonical accessor.
		YaraWorkerEnabled *bool `yaml:"yara_worker_enabled"`
	} `yaml:"signatures" hotreload:"restart"`

	WebUI struct {
		Enabled      bool   `yaml:"enabled"`
		Listen       string `yaml:"listen"`
		AuthToken    string `yaml:"auth_token"`
		MetricsToken string `yaml:"metrics_token" hotreload:"safe"` // optional Bearer token for /metrics; rotate via SIGHUP without restart
		TLSCert      string `yaml:"tls_cert"`
		TLSKey       string `yaml:"tls_key"`
		UIDir        string `yaml:"ui_dir"` // path to UI files on disk (default: /opt/csm/ui)

		// Tokens is the multi-credential model added in v2.12.0. Each entry has
		// a stable name (for audit), an opaque secret, and a scope that gates
		// which endpoints accept it. Legacy AuthToken is preserved during the
		// migration window so callers that read it directly keep working;
		// applyDefaults populates Tokens from AuthToken when only the legacy
		// field is set.
		Tokens []WebUIToken `yaml:"tokens,omitempty"`
	} `yaml:"webui" hotreload:"restart"`

	EmailAV EmailAVConfig `yaml:"email_av" hotreload:"restart"`

	EmailProtection struct {
		PasswordCheckIntervalMin int      `yaml:"password_check_interval_min"`
		HighVolumeSenders        []string `yaml:"high_volume_senders"`
		RateWarnThreshold        int      `yaml:"rate_warn_threshold"`
		RateCritThreshold        int      `yaml:"rate_crit_threshold"`
		RateWindowMin            int      `yaml:"rate_window_min"`
		KnownForwarders          []string `yaml:"known_forwarders"`

		// PHPRelay is the operator-tunable knob block for the email
		// PHP-relay protection feature (Stage 1). All thresholds default
		// to the values set in applyDefaults(); leaving any field at its
		// zero value triggers the documented default at load time.
		PHPRelay struct {
			Enabled                  bool    `yaml:"enabled"`
			RateWindowMin            int     `yaml:"rate_window_min"`
			HeaderScoreVolumeMin     int     `yaml:"header_score_volume_min"`
			AbsoluteVolumePerHour    int     `yaml:"absolute_volume_per_hour"`
			AccountVolumePerHour     int     `yaml:"account_volume_per_hour"`
			ReputationFailuresPer24h int     `yaml:"reputation_failures_per_24h"`
			FanoutDistinctScripts    int     `yaml:"fanout_distinct_scripts"`
			FanoutWindowMin          int     `yaml:"fanout_window_min"`
			BaselineSigma            float64 `yaml:"baseline_sigma"`
			BaselineObservationDays  int     `yaml:"baseline_observation_days"`
			PoliciesDir              string  `yaml:"policies_dir"`
		} `yaml:"php_relay"`

		// CloudRelay scopes opt-out for the email_cloud_relay_abuse
		// detector only. Use this when an operator legitimately runs a
		// mailer on a public-cloud VM (Google Cloud, AWS, etc.) and the
		// realtime/retro detectors keep false-firing on that mailbox.
		// AllowUsers matches full mailboxes (case-insensitive). AllowDomains
		// matches the domain part of the AUTH user (case-insensitive),
		// covering every mailbox under that domain. Either match exits
		// the detector before any window state is updated, so an
		// allowlisted mailbox cannot prime the counter for another user.
		// Leaving both empty preserves prior behavior. The shared
		// EmailProtection.HighVolumeSenders list still applies as well.
		CloudRelay struct {
			AllowUsers   []string `yaml:"allow_users"`
			AllowDomains []string `yaml:"allow_domains"`
		} `yaml:"cloud_relay"`
	} `yaml:"email_protection" hotreload:"safe"`

	Firewall *firewall.FirewallConfig `yaml:"firewall" hotreload:"restart"`

	GeoIP struct {
		AccountID      string   `yaml:"account_id"`
		LicenseKey     string   `yaml:"license_key"`
		Editions       []string `yaml:"editions"`
		AutoUpdate     *bool    `yaml:"auto_update"`     // nil = true when credentials set
		UpdateInterval string   `yaml:"update_interval"` // default "24h"
	} `yaml:"geoip" hotreload:"restart"`

	ModSecErrorLog string `yaml:"modsec_error_log" hotreload:"restart"`

	ModSec struct {
		RulesFile     string `yaml:"rules_file"`     // path to modsec2.user.conf
		OverridesFile string `yaml:"overrides_file"` // path to csm-overrides.conf
		ReloadCommand string `yaml:"reload_command"` // e.g. "systemctl restart lsws"
	} `yaml:"modsec" hotreload:"restart"`

	// WebServer overrides the auto-detected web server paths. Every field is
	// optional: anything left blank or empty falls back to what
	// platform.Detect() returned at startup. Intended for hosts with a
	// custom layout (reverse proxy in front of a second daemon, non-standard
	// package locations, chroot, etc.).
	WebServer struct {
		Type         string   `yaml:"type"`              // "apache", "nginx", "litespeed" -- overrides auto-detect
		ConfigDir    string   `yaml:"config_dir"`        // e.g. /etc/apache2 or /etc/nginx
		AccessLogs   []string `yaml:"access_logs"`       // candidate access-log paths, tried in order
		ErrorLogs    []string `yaml:"error_logs"`        // candidate error-log paths (used for modsec denies)
		ModSecAudits []string `yaml:"modsec_audit_logs"` // candidate ModSecurity audit-log paths
		// TrustedProxies is the list of IP addresses or CIDR ranges whose
		// X-Forwarded-For header is trusted for client IP extraction. When
		// the connecting IP is not in this list, XFF is ignored and
		// RemoteIP is used as-is.
		TrustedProxies []string `yaml:"trusted_proxies"` // IP/CIDR sources allowed to supply X-Forwarded-For
		// DomlogGlobs overrides the auto-detected per-vhost access-log glob
		// patterns. When set, the platform default for the detected panel/OS
		// is discarded and only these patterns are used. Leave empty to use
		// the auto-detected globs.
		DomlogGlobs []string `yaml:"domlog_globs"` // per-vhost access-log globs
	} `yaml:"web_server" hotreload:"restart"`

	// AccountRoots lets operators point the account-scan based checks at
	// non-cPanel web root layouts. Each entry is a glob pattern expanded
	// at check time. Examples:
	//
	//   account_roots:
	//     - /var/www/*/public
	//     - /srv/http/*
	//     - /home/*/public_html        # cPanel default (implicit when unset on cPanel)
	//
	// When unset, CSM uses the cPanel default of /home/*/public_html on
	// cPanel hosts and an empty list on non-cPanel hosts (account-scan
	// checks skip entirely). See docs/src/configuration.md for the full
	// list of checks that consume this.
	AccountRoots []string `yaml:"account_roots" hotreload:"restart"`

	Performance struct {
		Enabled                     *bool   `yaml:"enabled"`
		LoadHighMultiplier          float64 `yaml:"load_high_multiplier"`
		LoadCriticalMultiplier      float64 `yaml:"load_critical_multiplier"`
		PHPProcessWarnPerUser       int     `yaml:"php_process_warn_per_user"`
		PHPProcessCriticalTotalMult int     `yaml:"php_process_critical_total_multiplier"`
		ErrorLogWarnSizeMB          int     `yaml:"error_log_warn_size_mb"`
		MySQLJoinBufferMaxMB        int     `yaml:"mysql_join_buffer_max_mb"`
		MySQLWaitTimeoutMax         int     `yaml:"mysql_wait_timeout_max"`
		MySQLMaxConnectionsPerUser  int     `yaml:"mysql_max_connections_per_user"`
		RedisBgsaveMinInterval      int     `yaml:"redis_bgsave_min_interval"`
		RedisLargeDatasetGB         int     `yaml:"redis_large_dataset_gb"`
		WPMemoryLimitMaxMB          int     `yaml:"wp_memory_limit_max_mb"`
		WPTransientWarnMB           int     `yaml:"wp_transient_warn_mb"`
		WPTransientCriticalMB       int     `yaml:"wp_transient_critical_mb"`
	} `yaml:"performance" hotreload:"restart"`

	Cloudflare struct {
		Enabled      bool `yaml:"enabled"`
		RefreshHours int  `yaml:"refresh_hours"`
	} `yaml:"cloudflare" hotreload:"restart"`

	C2Blocklist   []string `yaml:"c2_blocklist" hotreload:"restart"`
	BackdoorPorts []int    `yaml:"backdoor_ports" hotreload:"restart"`

	// DisabledChecks lists check names that should be skipped entirely by
	// the runner (no execution, no finding, no email/webhook/audit). Use
	// this when a whole category does not apply to a host (e.g. WAF/web
	// checks on DNS-only cPanel servers). Distinct from
	// alerts.email.disabled_checks, which only suppresses email but still
	// runs the check and emits findings to other sinks.
	DisabledChecks []string `yaml:"disabled_checks" hotreload:"safe"`

	// Retention bounds bbolt growth. When enabled, a daily sweep prunes
	// per-bucket entries older than the configured TTL and an online
	// compaction pass shrinks the on-disk file once the fill ratio drops
	// below CompactFillRatio (and the file exceeds CompactMinSizeMB).
	// All fields are hot-reload:"restart" because the retention goroutine
	// captures these on daemon start.
	Retention struct {
		Enabled          bool    `yaml:"enabled"`             // opt-in
		FindingsDays     int     `yaml:"findings_days"`       // default 90
		HistoryDays      int     `yaml:"history_days"`        // default 30
		ReputationDays   int     `yaml:"reputation_days"`     // default 180
		SweepInterval    string  `yaml:"sweep_interval"`      // default "24h"
		CompactMinSizeMB int     `yaml:"compact_min_size_mb"` // default 128
		CompactFillRatio float64 `yaml:"compact_fill_ratio"`  // default 0.5
	} `yaml:"retention" hotreload:"restart"`

	// Sentry ships panics and selected errors to a Sentry server for
	// aggregation across hosts. Disabled by default; set enabled=true and
	// provide a DSN from the Sentry project. Init is one-shot: changes
	// require a daemon restart.
	Sentry struct {
		Enabled     bool    `yaml:"enabled"`
		DSN         string  `yaml:"dsn"`
		Environment string  `yaml:"environment"` // e.g. "production", "staging"
		SampleRate  float64 `yaml:"sample_rate"` // 0 -> 1.0 (capture all errors)
		Debug       bool    `yaml:"debug"`       // SDK debug logs to stderr
	} `yaml:"sentry" hotreload:"restart"`

	// MailLogs selects the log source for the postfix/dovecot brute-force
	// and relay detectors. Changing the source (file vs. journal) requires
	// the daemon to re-attach its reader, so the field is tagged restart.
	MailLogs MailLogsConfig `yaml:"mail_logs,omitempty" hotreload:"restart"`

	// Updates controls the upstream release-availability poll surfaced
	// in the Web UI top banner. The daemon never downloads or applies
	// updates -- it only tells the operator that a newer version
	// exists. Disable wholesale on air-gapped hosts.
	Updates struct {
		// CheckEnabled is a tri-state. nil means default-on; explicit
		// false disables the poll entirely (no outbound HTTP, no
		// package-manager probe). Use a pointer so the absence of the
		// key in YAML is distinguishable from `check_enabled: false`.
		CheckEnabled *bool `yaml:"check_enabled"`

		// Interval is parsed by time.ParseDuration. Defaults to 24h;
		// clamped to a 1h floor by updatecheck.New.
		Interval string `yaml:"interval"`

		// GitHubAPIURL overrides the default release endpoint. Tests
		// and air-gapped mirrors use this; leave empty in production.
		GitHubAPIURL string `yaml:"github_api_url,omitempty"`

		// PackageName is the apt/dnf package name to query when the
		// GitHub call fails. Defaults to "csm".
		PackageName string `yaml:"package_name,omitempty"`
	} `yaml:"updates" hotreload:"restart"`

	// Incidents groups correlator-side knobs the operator can tune
	// without code changes. Hot-reload "restart" because the daemon
	// captures these on startup; flipping mid-run would race the
	// retention loop.
	Incidents struct {
		// AutoClose resolves Open / Contained incidents whose UpdatedAt
		// exceeds the per-kind idle threshold. Default-on with safe
		// thresholds; mailbox takeover and credential spray expire at
		// 24h, web-account compromise at 7d, and host-level kinds never
		// auto-close. Operators who want to monitor decisions without
		// writing back can flip dry_run=true.
		AutoClose struct {
			// Enabled is tri-state: nil (default) means default-on; an
			// explicit false in YAML disables. Pointer so absence in YAML
			// is distinguishable from "enabled: false".
			Enabled *bool `yaml:"enabled"`
			DryRun  bool  `yaml:"dry_run"`
			// ByKind maps incident kind -> idle threshold (parsed by
			// time.ParseDuration). Kinds absent from the map are never
			// auto-closed. Use a string-keyed map so the operator can
			// add custom kinds without recompiling. Empty map falls back
			// to safe defaults (mailbox_takeover=24h,
			// credential_spray=24h, web_account_compromise=7d).
			ByKind map[string]string `yaml:"by_kind,omitempty"`
		} `yaml:"auto_close"`

		// SpraySuppression collapses one source IP brute-forcing many
		// distinct mailboxes/accounts into a single credential_spray
		// super-incident. Default-OFF + dry_run=TRUE so the path ships
		// dark; counters and audit log show what would have happened.
		// Operators flip enabled=true and dry_run=false after watching
		// the counters on their own infra.
		SpraySuppression struct {
			Enabled            bool     `yaml:"enabled"`
			DryRun             bool     `yaml:"dry_run"`
			DistinctMailboxes  int      `yaml:"distinct_mailboxes"`
			SeverityEscalateAt int      `yaml:"severity_escalate_at"`
			PerCheck           []string `yaml:"per_check"`
			MaxTrackedIPs      int      `yaml:"max_tracked_ips"`
			// BlockAtSeverity drives the firewall hand-off. Empty (default)
			// means detection-only: the super-incident opens and counters
			// move, but the IP is not blocked. "high" blocks as soon as the
			// detector trips at DistinctMailboxes. "critical" waits for the
			// severity escalation (SeverityEscalateAt distinct mailboxes)
			// before blocking. Auto_response.dry_run and block_ips still
			// gate the actual firewall call.
			BlockAtSeverity string `yaml:"block_at_severity"`
		} `yaml:"spray_suppression"`

		// AutoBlock is the generic incident-driven firewall hand-off.
		// Independent of SpraySuppression; applies to any non-spray
		// incident kind that carries a remote_ip in its correlation
		// key. Default-OFF so the path is dormant until an operator
		// opts in. Block requests still respect auto_response.enabled
		// and auto_response.block_ips at decision time.
		AutoBlock struct {
			Enabled         bool     `yaml:"enabled"`
			BlockAtSeverity string   `yaml:"block_at_severity"`
			Kinds           []string `yaml:"kinds"`
		} `yaml:"auto_block"`
	} `yaml:"incidents" hotreload:"restart"`
}

// UpdatesCheckEnabled reports the YAML-level state for the upstream
// release poll. Defaults to TRUE when omitted (most operators want
// the banner). Set `updates.check_enabled: false` to disable.
func (c *Config) UpdatesCheckEnabled() bool {
	return c.Updates.CheckEnabled == nil || *c.Updates.CheckEnabled
}

// UpdatesInterval returns the parsed poll interval. Falls back to
// 24h on parse error or when unset; updatecheck applies the floor.
func (c *Config) UpdatesInterval() time.Duration {
	if c.Updates.Interval == "" {
		return 24 * time.Hour
	}
	d, err := time.ParseDuration(c.Updates.Interval)
	if err != nil {
		return 24 * time.Hour
	}
	return d
}

// UpdatesPackageName returns the apt/dnf package name to query.
// Defaults to "csm".
func (c *Config) UpdatesPackageName() string {
	if c.Updates.PackageName == "" {
		return "csm"
	}
	return c.Updates.PackageName
}

// PHPRelayFreezeEnabled reports whether auto-freeze should run for the
// email PHP-relay detectors. Defaults to false when freeze was not set
// in YAML — the operator must opt in explicitly.
func (cfg *Config) PHPRelayFreezeEnabled() bool {
	return cfg.AutoResponse.PHPRelay.Freeze != nil && *cfg.AutoResponse.PHPRelay.Freeze
}

// IncidentsAutoCloseEnabled reports whether the auto-close path should
// run. Defaults to TRUE when the YAML key is absent so a fresh
// installation drains stale incidents without explicit opt-in. An
// explicit `incidents.auto_close.enabled: false` disables.
func (cfg *Config) IncidentsAutoCloseEnabled() bool {
	return cfg.Incidents.AutoClose.Enabled == nil || *cfg.Incidents.AutoClose.Enabled
}

// IncidentsAutoCloseThresholds returns the per-kind idle thresholds in
// parsed form. Built from the operator's by_kind YAML map, falling
// back to safe defaults (mailbox_takeover=24h, web_account_compromise=7d,
// credential_spray=24h) when the operator did not supply a map.
// Unparseable durations are skipped silently so a typo in one entry
// does not disable the rest.
func (cfg *Config) IncidentsAutoCloseThresholds() map[string]time.Duration {
	out := defaultIncidentAutoCloseThresholds()
	for kind, raw := range cfg.Incidents.AutoClose.ByKind {
		if raw == "" {
			delete(out, kind)
			continue
		}
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			continue
		}
		out[kind] = d
	}
	return out
}

func defaultIncidentAutoCloseThresholds() map[string]time.Duration {
	return map[string]time.Duration{
		"mailbox_takeover":       24 * time.Hour,
		"credential_spray":       24 * time.Hour,
		"web_account_compromise": 7 * 24 * time.Hour,
	}
}

// IncidentsAutoBlockKinds returns the configured kinds set in the shape
// the correlator expects. Empty result means "any non-spray kind".
func (cfg *Config) IncidentsAutoBlockKinds() map[string]bool {
	src := cfg.Incidents.AutoBlock.Kinds
	out := make(map[string]bool, len(src))
	for _, k := range src {
		if k == "" {
			continue
		}
		out[k] = true
	}
	return out
}

// IncidentsSpraySuppressionPerCheck returns the configured per-check map
// in the shape the correlator expects. Falls back to a safe default
// when the operator did not supply a list.
func (cfg *Config) IncidentsSpraySuppressionPerCheck() map[string]bool {
	src := cfg.Incidents.SpraySuppression.PerCheck
	if len(src) == 0 {
		src = []string{
			"email_auth_failure_realtime",
			"pam_auth_failure",
			"ssh_bruteforce",
		}
	}
	out := make(map[string]bool, len(src))
	for _, c := range src {
		if c == "" {
			continue
		}
		out[c] = true
	}
	return out
}

// PHPRelayDryRunEnabled reports the YAML-level dry-run state for the
// email PHP-relay auto-freeze. Defaults to TRUE when dry_run was not
// set, which is the safe shipped behaviour: an operator who enables
// freeze without thinking about dry-run gets a dry-run, not a live
// freeze. nil-or-explicit-true => true; explicit-false => false.
func (cfg *Config) PHPRelayDryRunEnabled() bool {
	return cfg.AutoResponse.PHPRelay.DryRun == nil || *cfg.AutoResponse.PHPRelay.DryRun
}

// AutoResponseDryRunEnabled mirrors PHPRelayDryRunEnabled: nil-or-true means true.
// When dry_run is absent from YAML the operator gets safe dry-run behaviour;
// explicit false is required to enable live nftables blocking.
func (cfg *Config) AutoResponseDryRunEnabled() bool {
	return cfg.AutoResponse.DryRun == nil || *cfg.AutoResponse.DryRun
}

// DirectSMTPEgressDryRunEnabled reports the YAML-level dry-run state
// for the direct SMTP egress detector. Defaults to TRUE when dry_run
// was omitted (safety default). Operators must explicitly set
// `dry_run: false` to flip the detector to active mode.
func (c *Config) DirectSMTPEgressDryRunEnabled() bool {
	if c.Detection.DirectSMTPEgress.DryRun == nil {
		return true
	}
	return *c.Detection.DirectSMTPEgress.DryRun
}

// BPFEnforcementDryRunEnabled reports the YAML-level dry-run state for
// BPF cgroup-deny enforcement. Defaults to TRUE when dry_run is omitted
// (safety default). Operators must explicitly set `dry_run: false` to
// flip the in-kernel program to live denial.
func (c *Config) BPFEnforcementDryRunEnabled() bool {
	if c.AutoResponseDryRunEnabled() {
		return true
	}
	if c.BPFEnforcement.DirectSMTPEgress && c.DirectSMTPEgressDryRunEnabled() {
		return true
	}
	if c.BPFEnforcement.DryRun == nil {
		return true
	}
	return *c.BPFEnforcement.DryRun
}

// BotVerifyEnabled reports whether async PTR+forward-A verification of
// claimed search-engine bots is on. Default true; explicit false is
// honored so operators on air-gapped networks can disable DNS calls.
func (c *Config) BotVerifyEnabled() bool {
	if c.Reputation.BotVerifyEnabled == nil {
		return true
	}
	return *c.Reputation.BotVerifyEnabled
}

type defaultPresence struct {
	smtpProbeThreshold bool
}

func applyDefaults(cfg *Config, presence defaultPresence) {
	// Defaults
	if cfg.StatePath == "" {
		cfg.StatePath = "/var/lib/csm/state"
	}
	if cfg.Alerts.AuditLog.File.Enabled && cfg.Alerts.AuditLog.File.Path == "" {
		cfg.Alerts.AuditLog.File.Path = "/var/log/csm/audit.jsonl"
	}
	if cfg.Alerts.AuditLog.Syslog.Enabled {
		if cfg.Alerts.AuditLog.Syslog.Network == "" {
			cfg.Alerts.AuditLog.Syslog.Network = "udp"
		}
		if cfg.Alerts.AuditLog.Syslog.Facility == "" {
			cfg.Alerts.AuditLog.Syslog.Facility = "local0"
		}
	}
	if cfg.Alerts.Webhook.HMACSecretEnv != "" {
		if v := os.Getenv(cfg.Alerts.Webhook.HMACSecretEnv); v != "" {
			cfg.Alerts.Webhook.HMACSecret = v
		}
	}

	if cfg.Signatures.RulesDir == "" {
		cfg.Signatures.RulesDir = "/opt/csm/rules"
	}
	if cfg.Signatures.YaraForge.Tier == "" {
		cfg.Signatures.YaraForge.Tier = "core"
	}
	if cfg.Signatures.YaraForge.UpdateInterval == "" {
		cfg.Signatures.YaraForge.UpdateInterval = "168h"
	}
	if cfg.WebUI.Listen == "" {
		cfg.WebUI.Listen = "0.0.0.0:9443"
	}
	if cfg.WebUI.AuthToken != "" && len(cfg.WebUI.Tokens) == 0 {
		cfg.WebUI.Tokens = []WebUIToken{{
			Name: "legacy-auth-token", Token: cfg.WebUI.AuthToken, Scope: "admin",
		}}
	}
	if cfg.Thresholds.MailQueueWarn == 0 {
		cfg.Thresholds.MailQueueWarn = 500
	}
	if cfg.Thresholds.MailQueueCrit == 0 {
		cfg.Thresholds.MailQueueCrit = 2000
	}
	if cfg.Thresholds.StateExpiryHours == 0 {
		cfg.Thresholds.StateExpiryHours = 24
	}
	if cfg.Thresholds.DeepScanIntervalMin == 0 {
		cfg.Thresholds.DeepScanIntervalMin = 60
	}
	if cfg.Thresholds.WPCoreCheckIntervalMin == 0 {
		cfg.Thresholds.WPCoreCheckIntervalMin = 60
	}
	if cfg.Thresholds.WebshellScanIntervalMin == 0 {
		cfg.Thresholds.WebshellScanIntervalMin = 30
	}
	if cfg.Thresholds.FilesystemScanIntervalMin == 0 {
		cfg.Thresholds.FilesystemScanIntervalMin = 30
	}
	if cfg.Thresholds.PluginCheckIntervalMin == 0 {
		cfg.Thresholds.PluginCheckIntervalMin = 1440
	}
	if cfg.Thresholds.BruteForceWindow == 0 {
		cfg.Thresholds.BruteForceWindow = 5000
	}
	if cfg.Thresholds.DomlogMaxFiles == 0 {
		cfg.Thresholds.DomlogMaxFiles = 500
	}
	if cfg.Thresholds.AccountScanMaxFiles == 0 {
		cfg.Thresholds.AccountScanMaxFiles = 10000
	}
	if cfg.Thresholds.CrontabBase64BlobMaxBytes == 0 {
		cfg.Thresholds.CrontabBase64BlobMaxBytes = 16384
	}
	if cfg.Thresholds.DomlogTailLines == 0 {
		cfg.Thresholds.DomlogTailLines = 500
	}
	if cfg.Thresholds.DomlogMaxAgeMin == 0 {
		cfg.Thresholds.DomlogMaxAgeMin = 30
	}
	if cfg.Thresholds.MailLogTailLines == 0 {
		cfg.Thresholds.MailLogTailLines = 500
	}
	if cfg.Thresholds.SyslogMessagesTailLines == 0 {
		cfg.Thresholds.SyslogMessagesTailLines = 200
	}
	if cfg.Thresholds.CredStuffingDistinctAccounts == 0 {
		cfg.Thresholds.CredStuffingDistinctAccounts = 5
	}
	if cfg.Thresholds.ModSecEscalationHits == 0 {
		cfg.Thresholds.ModSecEscalationHits = 3
	}
	if cfg.Thresholds.ModSecEscalationWindowMin == 0 {
		cfg.Thresholds.ModSecEscalationWindowMin = 10
	}
	if cfg.Thresholds.HTTPFloodWindowMin <= 0 {
		cfg.Thresholds.HTTPFloodWindowMin = 5
	}
	// HTTPFloodThreshold has no nonzero default: 0 means disabled and
	// that is the shipped behavior.
	if cfg.Thresholds.HTTPUASpoofThreshold <= 0 {
		cfg.Thresholds.HTTPUASpoofThreshold = 30
	}
	if cfg.Thresholds.SMTPBruteForceThreshold == 0 {
		cfg.Thresholds.SMTPBruteForceThreshold = 5
	}
	if cfg.Thresholds.SMTPBruteForceWindowMin == 0 {
		cfg.Thresholds.SMTPBruteForceWindowMin = 10
	}
	if cfg.Thresholds.SMTPBruteForceSuppressMin == 0 {
		cfg.Thresholds.SMTPBruteForceSuppressMin = 60
	}
	if cfg.Thresholds.SMTPBruteForceSubnetThresh == 0 {
		cfg.Thresholds.SMTPBruteForceSubnetThresh = 8
	}
	if cfg.Thresholds.SMTPAccountSprayThreshold == 0 {
		cfg.Thresholds.SMTPAccountSprayThreshold = 12
	}
	if cfg.Thresholds.SMTPBruteForceMaxTracked == 0 {
		cfg.Thresholds.SMTPBruteForceMaxTracked = 20000
	}
	if cfg.Thresholds.SMTPProbeThreshold == 0 && !presence.smtpProbeThreshold {
		cfg.Thresholds.SMTPProbeThreshold = 100
	}
	if cfg.Thresholds.SMTPProbeWindowMin == 0 {
		cfg.Thresholds.SMTPProbeWindowMin = 5
	}
	if cfg.Thresholds.SMTPProbeSuppressMin == 0 {
		cfg.Thresholds.SMTPProbeSuppressMin = 60
	}
	if cfg.Thresholds.SMTPProbeMaxTracked == 0 {
		cfg.Thresholds.SMTPProbeMaxTracked = 20000
	}
	if cfg.Thresholds.MailBruteForceThreshold == 0 {
		cfg.Thresholds.MailBruteForceThreshold = 5
	}
	if cfg.Thresholds.MailBruteForceWindowMin == 0 {
		cfg.Thresholds.MailBruteForceWindowMin = 10
	}
	if cfg.Thresholds.MailBruteForceSuppressMin == 0 {
		cfg.Thresholds.MailBruteForceSuppressMin = 60
	}
	if cfg.Thresholds.MailBruteForceSubnetThresh == 0 {
		cfg.Thresholds.MailBruteForceSubnetThresh = 8
	}
	if cfg.Thresholds.MailAccountSprayThreshold == 0 {
		cfg.Thresholds.MailAccountSprayThreshold = 12
	}
	if cfg.Thresholds.MailBruteForceMaxTracked == 0 {
		cfg.Thresholds.MailBruteForceMaxTracked = 20000
	}
	if cfg.Alerts.MaxPerHour == 0 {
		cfg.Alerts.MaxPerHour = 30
	}
	if cfg.Challenge.ListenAddr == "" {
		cfg.Challenge.ListenAddr = "127.0.0.1"
	}
	if cfg.Challenge.ListenPort == 0 {
		cfg.Challenge.ListenPort = 8439
	}
	if cfg.Challenge.Difficulty == 0 {
		cfg.Challenge.Difficulty = 2
	}
	if cfg.Firewall == nil {
		cfg.Firewall = firewall.DefaultConfig()
	}
	if len(cfg.GeoIP.Editions) == 0 {
		cfg.GeoIP.Editions = []string{"GeoLite2-City", "GeoLite2-ASN"}
	}
	if cfg.GeoIP.UpdateInterval == "" {
		cfg.GeoIP.UpdateInterval = "24h"
	}
	EmailAVDefaults(&cfg.EmailAV)

	if cfg.EmailProtection.PasswordCheckIntervalMin == 0 {
		cfg.EmailProtection.PasswordCheckIntervalMin = 1440
	}
	if cfg.EmailProtection.RateWarnThreshold == 0 {
		cfg.EmailProtection.RateWarnThreshold = 50
	}
	if cfg.EmailProtection.RateCritThreshold == 0 {
		cfg.EmailProtection.RateCritThreshold = 100
	}
	if cfg.EmailProtection.RateWindowMin == 0 {
		cfg.EmailProtection.RateWindowMin = 10
	}

	// EmailProtection.PHPRelay defaults. Freeze/DryRun are *bool and
	// remain nil here -- accessors resolve the safe defaults
	// (PHPRelayFreezeEnabled / PHPRelayDryRunEnabled) so we do NOT
	// mutate them. AccountVolumePerHour stays at 0 by default to mark
	// "auto-derive from cPanel maxemailsperhour" downstream.
	if cfg.EmailProtection.PHPRelay.RateWindowMin == 0 {
		cfg.EmailProtection.PHPRelay.RateWindowMin = 5
	}
	if cfg.EmailProtection.PHPRelay.HeaderScoreVolumeMin == 0 {
		cfg.EmailProtection.PHPRelay.HeaderScoreVolumeMin = 5
	}
	if cfg.EmailProtection.PHPRelay.AbsoluteVolumePerHour == 0 {
		cfg.EmailProtection.PHPRelay.AbsoluteVolumePerHour = 30
	}
	if cfg.EmailProtection.PHPRelay.ReputationFailuresPer24h == 0 {
		cfg.EmailProtection.PHPRelay.ReputationFailuresPer24h = 3
	}
	if cfg.EmailProtection.PHPRelay.FanoutDistinctScripts == 0 {
		cfg.EmailProtection.PHPRelay.FanoutDistinctScripts = 3
	}
	if cfg.EmailProtection.PHPRelay.FanoutWindowMin == 0 {
		cfg.EmailProtection.PHPRelay.FanoutWindowMin = 5
	}
	if cfg.EmailProtection.PHPRelay.BaselineSigma == 0 {
		cfg.EmailProtection.PHPRelay.BaselineSigma = 3.0
	}
	if cfg.EmailProtection.PHPRelay.BaselineObservationDays == 0 {
		cfg.EmailProtection.PHPRelay.BaselineObservationDays = 7
	}
	if cfg.EmailProtection.PHPRelay.PoliciesDir == "" {
		cfg.EmailProtection.PHPRelay.PoliciesDir = "/opt/csm/policies/php_relay"
	}
	if cfg.AutoResponse.PHPRelay.MaxActionsPerMinute == 0 {
		cfg.AutoResponse.PHPRelay.MaxActionsPerMinute = 60
	}
	if cfg.AutoResponse.MaxBlocksPerHour == 0 {
		cfg.AutoResponse.MaxBlocksPerHour = DefaultMaxBlocksPerHour
	}

	// Performance defaults.
	// Enabled is a tri-state *bool: nil means "use system default (on)", true means
	// explicitly enabled, false means explicitly disabled. We do NOT apply a default
	// here so that callers can distinguish "operator left it unset" (nil) from
	// "operator set it to true" (&true). All callers must nil-check before dereferencing;
	// perfEnabled() in checks/performance.go treats nil as true.
	if cfg.Performance.LoadHighMultiplier == 0 {
		cfg.Performance.LoadHighMultiplier = 1.0
	}
	if cfg.Performance.LoadCriticalMultiplier == 0 {
		cfg.Performance.LoadCriticalMultiplier = 2.0
	}
	if cfg.Performance.PHPProcessWarnPerUser == 0 {
		cfg.Performance.PHPProcessWarnPerUser = 20
	}
	if cfg.Performance.PHPProcessCriticalTotalMult == 0 {
		cfg.Performance.PHPProcessCriticalTotalMult = 5
	}
	if cfg.Performance.ErrorLogWarnSizeMB == 0 {
		cfg.Performance.ErrorLogWarnSizeMB = 50
	}
	if cfg.Performance.MySQLJoinBufferMaxMB == 0 {
		cfg.Performance.MySQLJoinBufferMaxMB = 64
	}
	if cfg.Performance.MySQLWaitTimeoutMax == 0 {
		cfg.Performance.MySQLWaitTimeoutMax = 3600
	}
	if cfg.Performance.MySQLMaxConnectionsPerUser == 0 {
		cfg.Performance.MySQLMaxConnectionsPerUser = 10
	}
	if cfg.Performance.RedisBgsaveMinInterval == 0 {
		cfg.Performance.RedisBgsaveMinInterval = 900
	}
	if cfg.Performance.RedisLargeDatasetGB == 0 {
		cfg.Performance.RedisLargeDatasetGB = 4
	}
	if cfg.Performance.WPMemoryLimitMaxMB == 0 {
		cfg.Performance.WPMemoryLimitMaxMB = 512
	}
	if cfg.Performance.WPTransientWarnMB == 0 {
		cfg.Performance.WPTransientWarnMB = 1
	}
	if cfg.Performance.WPTransientCriticalMB == 0 {
		cfg.Performance.WPTransientCriticalMB = 10
	}

	if cfg.Cloudflare.RefreshHours == 0 {
		cfg.Cloudflare.RefreshHours = 6
	}

	// Retention: defaults apply whether or not the feature is enabled, so
	// that flipping `enabled: true` without further tuning gives the
	// documented behaviour.
	if cfg.Retention.FindingsDays == 0 {
		cfg.Retention.FindingsDays = 90
	}
	if cfg.Retention.HistoryDays == 0 {
		cfg.Retention.HistoryDays = 30
	}
	if cfg.Retention.ReputationDays == 0 {
		cfg.Retention.ReputationDays = 180
	}
	if cfg.Retention.SweepInterval == "" {
		cfg.Retention.SweepInterval = "24h"
	}
	if cfg.Retention.CompactMinSizeMB == 0 {
		cfg.Retention.CompactMinSizeMB = 128
	}
	if cfg.Retention.CompactFillRatio == 0 {
		cfg.Retention.CompactFillRatio = 0.5
	}

	if cfg.MailLogs.Source == "" {
		cfg.MailLogs.Source = "auto"
	}
	if len(cfg.MailLogs.Units) == 0 {
		cfg.MailLogs.Units = []string{"postfix", "dovecot"}
	}

	if cfg.Updates.Interval == "" {
		cfg.Updates.Interval = "24h"
	}
	if cfg.Updates.PackageName == "" {
		cfg.Updates.PackageName = "csm"
	}

	if cfg.Thresholds.MailBruteAccountKey == "" {
		cfg.Thresholds.MailBruteAccountKey = "builtin:dovecot-user"
	}

	if cfg.Reputation.Rspamd.URL == "" {
		cfg.Reputation.Rspamd.URL = "http://127.0.0.1:11334"
	}
	// Token resolution happens at query time (see RspamdSource.Score).

	if cfg.Reputation.Upstream.CacheTTLMin == 0 {
		cfg.Reputation.Upstream.CacheTTLMin = 15
	}
	if cfg.Reputation.Upstream.TimeoutSec == 0 {
		cfg.Reputation.Upstream.TimeoutSec = 5
	}
	// Token resolution happens at query time (UpstreamSource.resolveToken).

	if cfg.AutoResponse.VerdictCallback.TimeoutSec == 0 {
		cfg.AutoResponse.VerdictCallback.TimeoutSec = 2 // tight; the hook is on the block hot path
	}
	// Secret resolution happens at call time (verdict.Client reads env per call).

	// Direct SMTP egress detector defaults. Backend "auto" lets the runtime
	// pick BPF where available and fall back to legacy polling. Standard
	// submission/relay ports cover the bulk of mass-mail abuse seen in the
	// wild; operators can override via YAML to add e.g. 2525.
	if cfg.Detection.DirectSMTPEgress.Backend == "" {
		cfg.Detection.DirectSMTPEgress.Backend = "auto"
	}
	if len(cfg.Detection.DirectSMTPEgress.Ports) == 0 {
		cfg.Detection.DirectSMTPEgress.Ports = []int{25, 465, 587}
	}
}

// MaxConfigBytes caps the YAML config body size LoadBytes will parse.
// Real CSM configs (main + every drop-in fragment) top out near 64 KB
// even with verbose comments; 4 MB is several orders of magnitude
// above legitimate use and far below the size at which a malformed
// or attacker-supplied file would force the YAML parser to allocate
// gigabytes of intermediate state.
const MaxConfigBytes = 4 * 1024 * 1024

var errConfigTooLarge = errors.New("config input exceeds byte cap")

func readConfigBytesLimited(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > MaxConfigBytes {
		return nil, errConfigTooLarge
	}
	return data, nil
}

// LoadBytes decodes a YAML config body and applies all defaults,
// matching Load. ConfigFile is left empty; the caller sets it.
func LoadBytes(data []byte) (*Config, error) {
	if len(data) > MaxConfigBytes {
		return nil, fmt.Errorf("parsing config: input size %d exceeds %d byte cap", len(data), MaxConfigBytes)
	}
	presence, err := defaultPresenceFromYAML(data)
	if err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	cfg := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	applyDefaults(cfg, presence)
	if err := validateWebUITokens(cfg); err != nil {
		return nil, err
	}
	if err := validateMailLogs(cfg); err != nil {
		return nil, err
	}
	if err := validateMailBruteAccountKey(cfg); err != nil {
		return nil, err
	}
	if err := validateReputation(cfg); err != nil {
		return nil, err
	}
	if err := validateVerdictCallback(cfg); err != nil {
		return nil, err
	}
	if err := validateDirectSMTPEgress(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func defaultPresenceFromYAML(data []byte) (defaultPresence, error) {
	var presence defaultPresence
	if len(bytes.TrimSpace(data)) == 0 {
		return presence, nil
	}

	var raw struct {
		Thresholds map[string]yaml.Node `yaml:"thresholds"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return presence, err
	}
	_, presence.smtpProbeThreshold = raw.Thresholds["smtp_probe_threshold"]
	return presence, nil
}

func validateReputation(cfg *Config) error {
	up := cfg.Reputation.Upstream
	if up.CacheTTLMin != 0 && (up.CacheTTLMin < 1 || up.CacheTTLMin > 1440) {
		return fmt.Errorf("reputation.upstream.cache_ttl_min must be between 1 and 1440")
	}
	if up.TimeoutSec != 0 && (up.TimeoutSec < 1 || up.TimeoutSec > 60) {
		return fmt.Errorf("reputation.upstream.timeout_sec must be between 1 and 60")
	}
	if !up.Enabled {
		return nil
	}
	if strings.TrimSpace(up.URL) == "" {
		return fmt.Errorf("reputation.upstream.enabled=true but url is empty")
	}
	parsed, err := url.Parse(up.URL)
	if err != nil {
		return fmt.Errorf("reputation.upstream.url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("reputation.upstream.url must use http or https")
	}
	if parsed.Host == "" {
		return fmt.Errorf("reputation.upstream.url must include host")
	}
	if parsed.Scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
		return fmt.Errorf("reputation.upstream.url must use https for non-loopback hosts (bearer token would otherwise leak in plaintext)")
	}
	return nil
}

// isLoopbackHost keeps plain HTTP limited to same-host panel deployments.
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

func validateVerdictCallback(cfg *Config) error {
	_, err := validateVerdictCallbackField(cfg)
	return err
}

func validateVerdictCallbackField(cfg *Config) (string, error) {
	vc := cfg.AutoResponse.VerdictCallback
	if vc.TimeoutSec != 0 && (vc.TimeoutSec < 1 || vc.TimeoutSec > 30) {
		return "auto_response.verdict_callback.timeout_sec", fmt.Errorf("auto_response.verdict_callback.timeout_sec must be between 1 and 30")
	}
	if !vc.Enabled {
		return "", nil
	}
	rawURL := strings.TrimSpace(vc.URL)
	if rawURL == "" {
		return "auto_response.verdict_callback.url", fmt.Errorf("auto_response.verdict_callback.enabled=true but url is empty")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "auto_response.verdict_callback.url", fmt.Errorf("auto_response.verdict_callback.url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "auto_response.verdict_callback.url", fmt.Errorf("auto_response.verdict_callback.url must use http or https")
	}
	if parsed.Host == "" {
		return "auto_response.verdict_callback.url", fmt.Errorf("auto_response.verdict_callback.url must include host")
	}
	if err := validateVerdictCallbackSecret(verdictCallbackForValidation{
		HMACSecret:    vc.HMACSecret,
		HMACSecretEnv: vc.HMACSecretEnv,
		AllowUnsigned: vc.AllowUnsigned,
	}); err != nil {
		return verdictCallbackSecretField(vc.HMACSecretEnv), err
	}
	return "", nil
}

// validateVerdictCallbackSecret enforces fail-closed posture on the
// outbound HMAC: when the callback is enabled, either hmac_secret or the
// hmac_secret_env-named env var must resolve to a non-empty value, OR
// the operator must explicitly set allow_unsigned: true to acknowledge
// that requests and responses will run without integrity protection.
//
// Without this check a misconfigured deployment (env var typoed, secret
// not yet rotated in) silently emits unsigned POSTs while the daemon
// keeps reporting healthy, and any on-path actor can forge or replay
// block decisions.
func validateVerdictCallbackSecret(vc verdictCallbackForValidation) error {
	if vc.AllowUnsigned {
		return nil
	}
	if strings.TrimSpace(vc.HMACSecret) != "" {
		return nil
	}
	if vc.HMACSecretEnv != "" {
		if strings.TrimSpace(os.Getenv(vc.HMACSecretEnv)) != "" {
			return nil
		}
		return fmt.Errorf("auto_response.verdict_callback.enabled=true but env var %q is empty or unset; set the secret, or opt in with allow_unsigned: true", vc.HMACSecretEnv)
	}
	return fmt.Errorf("auto_response.verdict_callback.enabled=true requires hmac_secret or hmac_secret_env (or allow_unsigned: true to acknowledge unsigned requests and responses)")
}

// verdictCallbackForValidation isolates the fields validateVerdictCallbackSecret
// needs without re-spelling the anonymous struct literal in config.go.
type verdictCallbackForValidation struct {
	HMACSecret    string
	HMACSecretEnv string
	AllowUnsigned bool
}

func verdictCallbackSecretField(hmacSecretEnv string) string {
	if hmacSecretEnv != "" {
		return "auto_response.verdict_callback.hmac_secret_env"
	}
	return "auto_response.verdict_callback.hmac_secret"
}

func validateDirectSMTPEgress(cfg *Config) error {
	d := cfg.Detection.DirectSMTPEgress
	switch strings.ToLower(strings.TrimSpace(d.Backend)) {
	case "", "auto", "bpf", "legacy", "none":
	default:
		return fmt.Errorf("detection.direct_smtp_egress.backend must be auto, bpf, legacy, or none")
	}
	for i, p := range d.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("detection.direct_smtp_egress.ports[%d] must be between 1 and 65535", i)
		}
	}
	return nil
}

func validateBPFEnforcement(cfg *Config) error {
	if !cfg.BPFEnforcement.Enabled {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Detection.ConnectionTrackerBackend)) {
	case "", "auto", "bpf":
	case "legacy", "none":
		return fmt.Errorf("bpf_enforcement.enabled=true requires detection.connection_tracker_backend=auto or bpf")
	default:
		return fmt.Errorf("detection.connection_tracker_backend must be auto, bpf, legacy, or none")
	}
	gates := 0
	if cfg.BPFEnforcement.DirectSMTPEgress {
		if !cfg.Detection.DirectSMTPEgress.Enabled {
			return fmt.Errorf("bpf_enforcement.direct_smtp_egress requires detection.direct_smtp_egress.enabled=true")
		}
		switch strings.ToLower(strings.TrimSpace(cfg.Detection.DirectSMTPEgress.Backend)) {
		case "", "auto", "bpf":
		case "legacy", "none":
			return fmt.Errorf("bpf_enforcement.direct_smtp_egress requires detection.direct_smtp_egress.backend=auto or bpf")
		default:
			return fmt.Errorf("detection.direct_smtp_egress.backend must be auto, bpf, legacy, or none")
		}
		gates++
	}
	if gates == 0 {
		return fmt.Errorf("bpf_enforcement.enabled=true requires at least one feature gate (direct_smtp_egress)")
	}
	return nil
}

func validateWebUITokens(cfg *Config) error {
	seenNames := make(map[string]struct{}, len(cfg.WebUI.Tokens))
	seenTokens := make(map[string]struct{}, len(cfg.WebUI.Tokens))
	for i, tok := range cfg.WebUI.Tokens {
		name := strings.TrimSpace(tok.Name)
		if name == "" {
			return fmt.Errorf("webui.tokens[%d]: empty name", i)
		}
		if tok.Scope != "admin" && tok.Scope != "read" {
			return fmt.Errorf("webui.tokens[%d]: unknown scope %q (use admin or read)", i, tok.Scope)
		}
		if tok.Token == "" {
			return fmt.Errorf("webui.tokens[%d]: empty token", i)
		}
		if _, ok := seenNames[name]; ok {
			return fmt.Errorf("webui.tokens[%d]: duplicate name %q", i, tok.Name)
		}
		seenNames[name] = struct{}{}
		if _, ok := seenTokens[tok.Token]; ok {
			return fmt.Errorf("webui.tokens[%d]: duplicate token", i)
		}
		seenTokens[tok.Token] = struct{}{}
	}
	return nil
}

func validateMailLogsField(cfg *Config) (string, error) {
	switch cfg.MailLogs.Source {
	case "", "auto", "file", "journal":
	default:
		return "mail_logs.source", fmt.Errorf("mail_logs.source: must be auto, file, or journal (got %q)", cfg.MailLogs.Source)
	}
	for i, unit := range cfg.MailLogs.Units {
		if strings.TrimSpace(unit) == "" {
			return "mail_logs.units", fmt.Errorf("mail_logs.units[%d]: empty unit", i)
		}
	}
	return "", nil
}

func validateMailLogs(cfg *Config) error {
	_, err := validateMailLogsField(cfg)
	return err
}

func validateMailBruteAccountKeyField(cfg *Config) (string, error) {
	key := cfg.Thresholds.MailBruteAccountKey
	switch {
	case key == "", key == "builtin:dovecot-user", key == "builtin:postfix-sasl":
		// ok
	case strings.HasPrefix(key, "regex:"):
		re, err := regexp.Compile(strings.TrimPrefix(key, "regex:"))
		if err != nil {
			return "thresholds.mail_brute_account_key", fmt.Errorf("mail_brute_account_key: invalid regex: %w", err)
		}
		if re.NumSubexp() < 1 {
			return "thresholds.mail_brute_account_key", fmt.Errorf("mail_brute_account_key: regex must contain at least one capture group")
		}
	default:
		return "thresholds.mail_brute_account_key", fmt.Errorf("mail_brute_account_key: %q must be builtin:* or regex:*", key)
	}
	return "", nil
}

func validateMailBruteAccountKey(cfg *Config) error {
	_, err := validateMailBruteAccountKeyField(cfg)
	return err
}

func Load(path string) (*Config, error) {
	// #nosec G304 -- path is operator-supplied config file (CLI flag / env).
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	defer f.Close()
	data, err := readConfigBytesLimited(f)
	if errors.Is(err, errConfigTooLarge) {
		return nil, fmt.Errorf("config %s exceeds %d byte cap", path, MaxConfigBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	cfg, err := LoadBytes(data)
	if err != nil {
		return nil, err
	}
	cfg.ConfigFile = path
	return cfg, nil
}

// LoadWithDir loads the main config file and then merges every YAML fragment
// from confDir on top in lexicographic order. A missing confDir is not an
// error. Unknown fields in fragments are rejected (KnownFields=true).
func LoadWithDir(path, confDir string) (*Config, error) {
	// #nosec G304 -- path is operator-supplied (CLI flag).
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	defer f.Close()
	mainData, err := readConfigBytesLimited(f)
	if errors.Is(err, errConfigTooLarge) {
		return nil, fmt.Errorf("config %s exceeds %d byte cap", path, MaxConfigBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	var merged yaml.Node
	if unmarshalErr := yaml.Unmarshal(mainData, &merged); unmarshalErr != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, unmarshalErr)
	}

	frags, err := loadConfDirFragments(confDir)
	if err != nil {
		return nil, err
	}
	for _, frag := range frags {
		DeepMergeTracked(&merged, frag.node, func(keyPath, oldVal, newVal string) {
			fmt.Fprintf(os.Stderr, "confd: %s overrides %s: %q -> %q\n",
				frag.path,
				keyPath,
				redactConfigScalarForLog(keyPath, oldVal),
				redactConfigScalarForLog(keyPath, newVal),
			)
		})
	}

	mergedBytes, err := yaml.Marshal(&merged)
	if err != nil {
		return nil, fmt.Errorf("marshaling merged config: %w", err)
	}

	cfg, err := LoadBytes(mergedBytes)
	if err != nil {
		return nil, err
	}
	cfg.ConfigFile = path
	cfg.ConfigDir = confDir
	return cfg, nil
}

func Save(cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	return os.WriteFile(cfg.ConfigFile, data, 0600)
}
