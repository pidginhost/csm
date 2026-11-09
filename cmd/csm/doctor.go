package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/integration/webserver"
	"github.com/pidginhost/csm/internal/integrity"
	"github.com/pidginhost/csm/internal/netutil"
	"github.com/pidginhost/csm/internal/platform"
)

// DoctorCheck is one line item in a DoctorReport. Status is one of
// "ok", "warn", or "fail".
type DoctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // ok | warn | fail
	Message string `json:"message,omitempty"`
	Fix     string `json:"fix,omitempty"`
}

// DoctorReport is the top-level result of `csm doctor`.
type DoctorReport struct {
	OverallStatus string           `json:"overall_status"`
	Checks        []DoctorCheck    `json:"checks"`
	Snapshot      *health.Snapshot `json:"snapshot,omitempty"`
}

func runDoctor() {
	jsonOut := false
	challengeOnly := false
	for _, arg := range os.Args[2:] {
		switch arg {
		case "--json":
			jsonOut = true
		case "challenge":
			challengeOnly = true
		}
	}

	if challengeOnly {
		report := buildChallengeDoctorReport(tryLoadConfigLite, defaultChallengeWebserverChecks, defaultChallengeGateProbe)
		emitDoctor(report, jsonOut)
		return
	}

	report := buildDoctorReport(tryLoadConfigLite, func() ([]byte, error) {
		return sendControl(control.CmdStatus, nil)
	}, func(cfg *config.Config) error {
		return integrity.Verify(binaryPath, cfg)
	})
	emitDoctor(report, jsonOut)
}

func buildDoctorReport(loadConfig func() (*config.Config, error), readStatus func() ([]byte, error), verifyIntegrity func(*config.Config) error) DoctorReport {
	report := DoctorReport{}

	// 1. Config validation (offline). Keep this path JSON-friendly: runDoctor
	// must not call loadConfigLite directly because that helper exits on error.
	cfg, err := loadConfig()
	if err != nil {
		report.Checks = append(report.Checks, DoctorCheck{
			Name:    "config valid",
			Status:  "fail",
			Message: err.Error(),
			Fix:     "edit csm.yaml or the failing conf.d fragment, then run `csm validate`",
		})
		report.OverallStatus = collapseDoctor(report.Checks)
		return report
	}
	modeCheckIndex := len(report.Checks)
	report.Checks = append(report.Checks, doctorModeCheck(cfg))
	validationChecks, invalid := doctorConfigValidation(cfg)
	report.Checks = append(report.Checks, validationChecks...)
	if invalid {
		report.OverallStatus = collapseDoctor(report.Checks)
		return report
	}

	// 1b. Integrity baseline (offline). The running daemon keeps its old
	// hashes, so a drop-in rewritten after the last signing only surfaces
	// when the next restart refuses to start. Checking here, before the
	// daemon probe, also puts the remedy in front of an operator whose
	// daemon is already down for that reason.
	report.Checks = append(report.Checks, doctorIntegrityCheck(cfg, verifyIntegrity))
	report.Checks = append(report.Checks, doctorAccountRootAccess(cfg)...)

	// 2. Daemon reachable
	resp, err := readStatus()
	if err != nil {
		report.Checks = append(report.Checks, DoctorCheck{
			Name:    "daemon reachable",
			Status:  "fail",
			Message: err.Error(),
			Fix:     "systemctl start csm.service",
		})
		report.OverallStatus = collapseDoctor(report.Checks)
		return report
	}
	report.Checks = append(report.Checks, DoctorCheck{Name: "daemon reachable", Status: "ok"})

	// 3. Snapshot-derived checks
	var sr control.StatusResult
	if err := json.Unmarshal(resp, &sr); err != nil {
		report.Checks = append(report.Checks, DoctorCheck{
			Name:    "health snapshot available",
			Status:  "fail",
			Message: fmt.Sprintf("daemon status response is not valid JSON: %v", err),
			Fix:     "restart csm.service and inspect daemon logs",
		})
		report.OverallStatus = collapseDoctor(report.Checks)
		return report
	}
	if sr.Snapshot == nil {
		report.Checks = append(report.Checks, DoctorCheck{
			Name:    "health snapshot available",
			Status:  "fail",
			Message: "daemon status response did not include a health snapshot",
			Fix:     "upgrade or restart csm.service",
		})
		report.OverallStatus = collapseDoctor(report.Checks)
		return report
	}

	report.Snapshot = sr.Snapshot
	report.Checks[modeCheckIndex] = doctorLiveModeCheck(cfg, sr.Snapshot.Mode)
	report.Checks = append(report.Checks, DoctorCheck{Name: "health snapshot available", Status: "ok"})
	if len(sr.Snapshot.Watchers) == 0 {
		report.Checks = append(report.Checks, DoctorCheck{
			Name:    "watchers registered",
			Status:  "fail",
			Message: "daemon reported no watcher attachment state",
			Fix:     "restart csm.service and inspect startup logs",
		})
	}
	for name, attached := range sr.Snapshot.Watchers {
		st := DoctorCheck{Name: "watcher: " + name}
		if attached {
			st.Status = "ok"
		} else {
			st.Status = "fail"
			st.Message = "watcher failed to attach"
			st.Fix = fmt.Sprintf("check daemon logs: journalctl -u csm.service -g %q", name)
		}
		report.Checks = append(report.Checks, st)
	}
	if !sr.Snapshot.StoreHealthy {
		report.Checks = append(report.Checks, DoctorCheck{
			Name:    "bbolt store healthy",
			Status:  "fail",
			Message: "store missing required buckets",
			Fix:     "stop daemon, run `csm store import <last-good>` or `csm baseline --confirm`",
		})
	} else {
		report.Checks = append(report.Checks, DoctorCheck{Name: "bbolt store healthy", Status: "ok"})
	}

	report.Checks = append(report.Checks, correlationAttributionCheck(sr.Snapshot.CorrelationAttribution))
	report.Checks = append(report.Checks, queueDoctorChecks(sr.Snapshot.Queues, sr.Snapshot.Automation)...)
	report.Checks = append(report.Checks, admissionDoctorChecks(sr.Snapshot.Admission)...)

	if automation := sr.Snapshot.Automation; automation.FirewallEnabled {
		check := DoctorCheck{Name: "firewall managed", Status: "ok"}
		if !automation.FirewallManaged {
			check.Status = "fail"
			check.Message = "firewall is enabled but CSM could not initialize its engine"
			if automation.FirewallStartupError != "" {
				check.Message += ": " + automation.FirewallStartupError
			}
			check.Fix = "inspect journalctl -u csm.service for the firewall startup error, correct the configuration or nftables permissions, then restart csm.service"
		}
		report.Checks = append(report.Checks, check)
		if automation.FirewallStateSetAside != "" {
			report.Checks = append(report.Checks, DoctorCheck{
				Name:    "firewall state",
				Status:  "fail",
				Message: "the firewall state file could not be read at startup; it was kept at " + automation.FirewallStateSetAside + " and its blocked and allowed addresses could not be restored",
				Fix:     "review the kept file, add back the entries that must stay, then restart csm.service to clear this check",
			})
		}
		if automation.FirewallLedgerError != "" {
			// 1.5c-1 ruling 7: a warning while admission previews, a
			// failure once it executes automatic blocks.
			closing, outage := admission.DoctorImpact(admissionExecuting(sr.Snapshot.Admission))
			report.Checks = append(report.Checks, DoctorCheck{
				Name:    "firewall automatic blocks",
				Status:  outage,
				Message: "the admission ledger could not be read when the firewall started: " + automation.FirewallLedgerError + "; the automatic blocks it wrote were restored without proof of their outcome and none is evicted until a restart reads it; " + closing,
				Fix:     "resolve the ledger error the admission checks report, then restart csm.service",
			})
		}
	}

	if w := sr.Snapshot.Automation.FirewallConfirmation; w != nil {
		check := DoctorCheck{
			Name: "firewall confirmation", Status: "warn",
			Message: "an apply-confirmed firewall change waits for confirmation and rolls back at " + w.Deadline.UTC().Format(time.RFC3339),
			Fix:     "run `csm firewall confirm` to keep it, or let it roll back",
		}
		if w.Error != "" {
			check.Status = "fail"
			check.Message = "an apply-confirmed firewall change cannot settle by itself: " + w.Error
			check.Fix = "inspect `nft list ruleset` and the firewall settings, then run `csm firewall confirm` to accept the current state; repair the reported recovery problem and restart the daemon to retry"
		}
		report.Checks = append(report.Checks, check)
	}

	// Termination depends on a kernel that can pin a process handle. Report it
	// only where it is configured, so hosts that never kill processes are not
	// asked to act on a capability they do not use.
	if automation := sr.Snapshot.Automation; automation.ProcessKillEnabled {
		check := DoctorCheck{Name: "process termination supported", Status: "ok"}
		if !automation.ProcessSignalSupported {
			check.Status = "fail"
			check.Message = "auto_response.kill_processes is enabled but this kernel cannot signal a pinned process handle"
			if automation.ProcessSignalError != "" {
				check.Message += ": " + automation.ProcessSignalError
			}
			check.Fix = "run a kernel providing pidfd_send_signal (Linux 5.1+, including EL8 backports), or set auto_response.kill_processes: false so detections are not silently left unremediated"
		}
		report.Checks = append(report.Checks, check)
	}

	// An operator copy of a deploy script is never upgraded in place, so a
	// version predating mandatory verification keeps installing unverified
	// releases until somebody reads it.
	report.Checks = append(report.Checks, deployScriptDoctorChecks()...)
	report.Checks = append(report.Checks, smtpAuthLoggingDoctorChecks()...)

	if cfg.PHPShield.Enabled {
		report.Checks = append(report.Checks, phpShieldCageFSDoctorChecks()...)
	}

	report.OverallStatus = collapseDoctor(report.Checks)
	return report
}

func doctorIntegrityCheck(cfg *config.Config, verify func(*config.Config) error) DoctorCheck {
	check := DoctorCheck{Name: "integrity baseline"}
	err := verify(cfg)
	if err == nil {
		if cfg.Integrity.BinaryHash == "" || cfg.Integrity.ConfigHash == "" {
			check.Status = "warn"
			check.Message = "integrity baseline is incomplete, so the binary and configuration are not fully verified"
			check.Fix = "run `csm baseline` on a new host, or `csm rehash` to record the current binary and configuration hashes"
			return check
		}
		check.Status = "ok"
		return check
	}
	check.Status = "fail"
	check.Message = err.Error()
	switch {
	case errors.Is(err, integrity.ErrConfdHashMismatch):
		check.Fix = "the next restart will refuse to start: run `csm rehash` if the conf.d change was intentional; for a fragment its owning integration rewrites, list it under confd.integrity_exempt in csm.yaml and rehash once"
	case errors.Is(err, integrity.ErrConfigHashMismatch):
		check.Fix = "the next restart will refuse to start: run `csm rehash` if you edited csm.yaml on purpose; otherwise treat the edit as tampering"
	case errors.Is(err, integrity.ErrBinaryHashMismatch):
		check.Fix = "run `csm rehash` after a deliberate binary upgrade; otherwise treat it as tampering and reinstall from a trusted package"
	default:
		check.Fix = "fix the read error, then run `csm verify`"
	}
	return check
}

// Disk config is only the next-start posture. A SIGHUP can re-sign a mode
// change while leaving the running daemon in its previous posture.
func doctorModeCheck(cfg *config.Config) DoctorCheck {
	mode := config.ModeEnforce
	if cfg.ObserveMode() {
		mode = config.ModeObserve
	}
	return DoctorCheck{
		Name:    "configured mode",
		Status:  "ok",
		Message: mode + " (applies at daemon startup)",
	}
}

func doctorLiveModeCheck(cfg *config.Config, running string) DoctorCheck {
	configured := config.ModeEnforce
	if cfg.ObserveMode() {
		configured = config.ModeObserve
	}
	check := DoctorCheck{Name: "operating mode", Status: "ok", Message: running}
	switch {
	case running != config.ModeObserve && running != config.ModeEnforce:
		check.Status = "warn"
		check.Message = "daemon did not report a supported operating mode (configured: " + configured + ")"
		check.Fix = "upgrade or restart csm.service, then check the running mode again"
	case running != configured:
		check.Status = "warn"
		check.Message = "running " + running + "; configured " + configured + " (restart required)"
		check.Fix = "systemctl restart csm.service"
	case running == config.ModeObserve:
		check.Message += " (no automatic remediation or integration changes)"
	default:
		check.Message += " (subsystems act under their own switches)"
	}
	return check
}

func doctorConfigValidation(cfg *config.Config) ([]DoctorCheck, bool) {
	var details []DoctorCheck
	errors := 0
	// The firewall deep probe compares the policy against the host's real SSH
	// listen ports. Doctor is where an operator looks before enabling the
	// firewall, so a pending lockout has to show up here.
	results := append(config.Validate(cfg), config.ValidateDeepSection(cfg, "firewall")...)
	for _, result := range results {
		check := DoctorCheck{Name: "config: " + result.Field, Message: result.Message}
		switch result.Level {
		case "error":
			check.Status = "fail"
			errors++
		case "warn":
			check.Status = "warn"
		default:
			continue
		}
		details = append(details, check)
	}

	summary := DoctorCheck{Name: "config valid", Status: "ok"}
	if errors > 0 {
		summary.Status = "fail"
		summary.Message = fmt.Sprintf("%d validation error(s)", errors)
		summary.Fix = "edit csm.yaml or the failing conf.d fragment, then run `csm validate`"
	}
	return append([]DoctorCheck{summary}, details...), errors > 0
}

type challengeWebserverChecksFunc func(*config.Config) []DoctorCheck
type challengeGateProbeFunc func(*config.Config) DoctorCheck

func buildChallengeDoctorReport(loadConfig func() (*config.Config, error), webChecks challengeWebserverChecksFunc, gateProbe challengeGateProbeFunc) DoctorReport {
	report := DoctorReport{}
	cfg, err := loadConfig()
	if err != nil {
		report.Checks = append(report.Checks, DoctorCheck{
			Name:    "config valid",
			Status:  "fail",
			Message: err.Error(),
			Fix:     "edit csm.yaml or the failing conf.d fragment, then run `csm validate`",
		})
		report.OverallStatus = collapseDoctor(report.Checks)
		return report
	}
	report.Checks = append(report.Checks, DoctorCheck{Name: "config valid", Status: "ok"})

	if !cfg.Challenge.Enabled {
		report.Checks = append(report.Checks, DoctorCheck{
			Name:    "challenge enabled",
			Status:  "warn",
			Message: "challenge.enabled is false",
			Fix:     "set challenge.enabled: true before installing webserver redirects",
		})
		report.OverallStatus = collapseDoctor(report.Checks)
		return report
	}
	report.Checks = append(report.Checks, DoctorCheck{Name: "challenge enabled", Status: "ok"})
	report.Checks = append(report.Checks, challengePublicURLCheck(cfg))
	report.Checks = append(report.Checks, challengeTrustedProxiesCheck(cfg))
	if _, socket := config.ChallengeSocketPath(cfg.Challenge.ListenAddr); socket {
		report.Checks = append(report.Checks, challengeSocketCheck(cfg))
	}
	report.Checks = append(report.Checks, challengeTLSCheck(cfg))
	report.Checks = append(report.Checks, challengePortGateCheck(cfg))
	if webChecks != nil {
		report.Checks = append(report.Checks, webChecks(cfg)...)
	}
	if gateProbe != nil {
		report.Checks = append(report.Checks, gateProbe(cfg))
	}
	report.OverallStatus = collapseDoctor(report.Checks)
	return report
}

func challengePublicURLCheck(cfg *config.Config) DoctorCheck {
	err := webserver.ValidateChallengePublicURL(webserver.RenderConfigFromConfig(cfg))
	if err != nil {
		return DoctorCheck{
			Name:    "challenge public URL",
			Status:  "fail",
			Message: err.Error(),
			Fix:     "set challenge.public_url to an absolute http(s) URL ending in /challenge, and bind challenge.listen_addr to a non-loopback address, or to " + config.ChallengeSocketExample + " for a proxy on this host",
		}
	}
	return DoctorCheck{Name: "challenge public URL", Status: "ok"}
}

// challengeTrustedProxiesCheck fails when trusted_proxies covers an address
// of this host. The challenge server refuses to start then, since any local
// account could pose as any visitor.
func challengeTrustedProxiesCheck(cfg *config.Config) DoctorCheck {
	if err := config.ChallengeLocalTrustError(cfg.Challenge.TrustedProxies); err != nil {
		return DoctorCheck{
			Name:    "challenge trusted proxies",
			Status:  "fail",
			Message: err.Error(),
			Fix:     "serve a proxy on this host through challenge.listen_addr: " + config.ChallengeSocketExample + " with challenge.listen_group, or remove trusted_proxies and use direct mode",
		}
	}
	return DoctorCheck{Name: "challenge trusted proxies", Status: "ok"}
}

// challengeSocketCheck applies the server's own placement rules, so a host
// fact the config cannot show (a missing group, an unsafe directory) is
// reported before a restart fails on it.
func challengeSocketCheck(cfg *config.Config) DoctorCheck {
	path, _ := config.ChallengeSocketPath(cfg.Challenge.ListenAddr)
	if _, err := challenge.CheckSocketPlacement(path, cfg.Challenge.ListenGroup); err != nil {
		return DoctorCheck{
			Name:    "challenge socket",
			Status:  "fail",
			Message: err.Error(),
			Fix:     "set challenge.listen_group to the group your proxy runs as and keep the socket in a root-owned directory nobody else can write, such as /run/csm",
		}
	}
	return DoctorCheck{Name: "challenge socket", Status: "ok", Message: path}
}

func challengeTLSCheck(cfg *config.Config) DoctorCheck {
	cert, key, source := challengeRuntimeTLSMaterial(cfg)
	if _, socket := config.ChallengeSocketPath(cfg.Challenge.ListenAddr); socket && cert == "" && key == "" {
		return DoctorCheck{Name: "challenge TLS", Status: "ok", Message: "unix socket listener: the proxy serves HTTPS"}
	}
	if challengeListenAddrIsLoopbackDoctor(cfg.Challenge.ListenAddr) && cert == "" && key == "" {
		return DoctorCheck{Name: "challenge TLS", Status: "ok", Message: "loopback listener does not require TLS"}
	}
	if (cert == "") != (key == "") {
		return DoctorCheck{
			Name:    "challenge TLS",
			Status:  "fail",
			Message: "only one TLS file is configured for the public challenge listener",
			Fix:     "set both challenge.tls_cert and challenge.tls_key, or both webui.tls_cert and webui.tls_key",
		}
	}
	scheme := ""
	if u, err := url.Parse(strings.TrimSpace(cfg.Challenge.PublicURL)); err == nil {
		scheme = u.Scheme
	}
	if cert == "" || key == "" {
		if scheme == "https" {
			if challengeBehindProxy(cfg) {
				return DoctorCheck{Name: "challenge TLS", Status: "ok", Message: "challenge.trusted_proxies serve HTTPS for challenge.public_url; doctor does not check the proxy"}
			}
			return DoctorCheck{
				Name:    "challenge TLS",
				Status:  "fail",
				Message: "challenge.public_url is HTTPS but the public listener has no TLS cert/key",
				Fix:     "configure challenge.tls_cert and challenge.tls_key, or reuse the Web UI TLS pair",
			}
		}
		return DoctorCheck{
			Name:    "challenge TLS",
			Status:  "warn",
			Message: "public challenge listener is plain HTTP",
			Fix:     "prefer HTTPS for browser-facing challenge.public_url",
		}
	}
	for _, p := range []string{cert, key} {
		if _, err := os.Stat(p); err != nil {
			return DoctorCheck{
				Name:    "challenge TLS",
				Status:  "fail",
				Message: fmt.Sprintf("%s TLS file %q is not readable: %v", source, p, err),
				Fix:     "fix the TLS path or file permissions, then restart csm.service",
			}
		}
	}
	return DoctorCheck{Name: "challenge TLS", Status: "ok", Message: source + " TLS pair present"}
}

func challengeRuntimeTLSMaterial(cfg *config.Config) (cert, key, source string) {
	if cfg.Challenge.TLSCert != "" || cfg.Challenge.TLSKey != "" {
		return cfg.Challenge.TLSCert, cfg.Challenge.TLSKey, "challenge"
	}
	if _, socket := config.ChallengeSocketPath(cfg.Challenge.ListenAddr); socket || challengeListenAddrIsLoopbackDoctor(cfg.Challenge.ListenAddr) {
		return "", "", ""
	}
	if cfg.WebUI.TLSCert != "" || cfg.WebUI.TLSKey != "" {
		return cfg.WebUI.TLSCert, cfg.WebUI.TLSKey, "webui"
	}
	return "", "", ""
}

func challengePortGateCheck(cfg *config.Config) DoctorCheck {
	if _, socket := config.ChallengeSocketPath(cfg.Challenge.ListenAddr); socket {
		if cfg.Challenge.PortGate.Enabled {
			return DoctorCheck{
				Name:    "challenge port gate",
				Status:  "warn",
				Message: "port gate is enabled but the listener is a unix socket, so it has no effect",
			}
		}
		return DoctorCheck{Name: "challenge port gate", Status: "ok", Message: "unix socket listener has no TCP port"}
	}
	if challengeListenAddrIsLoopbackDoctor(cfg.Challenge.ListenAddr) {
		if cfg.Challenge.PortGate.Enabled {
			return DoctorCheck{
				Name:    "challenge port gate",
				Status:  "warn",
				Message: "port gate is enabled but the listener is loopback-only, so no off-host traffic can reach it",
			}
		}
		return DoctorCheck{Name: "challenge port gate", Status: "ok", Message: "loopback listener is not exposed off-host"}
	}
	if !cfg.Challenge.PortGate.Enabled {
		if challengeBehindProxy(cfg) {
			return DoctorCheck{Name: "challenge port gate", Status: "ok", Message: "browsers reach the listener through challenge.trusted_proxies; keep challenge.listen_port closed to everything except the proxy"}
		}
		return DoctorCheck{
			Name:    "challenge port gate",
			Status:  "warn",
			Message: "public challenge listener is not protected by challenge.port_gate.enabled",
			Fix:     "set challenge.port_gate.enabled: true before exposing the listener broadly",
		}
	}
	return DoctorCheck{Name: "challenge port gate", Status: "ok"}
}

// challengeBehindProxy reports a custom proxy deployment: browsers connect to
// the proxy, so listener TLS and the port gate are not what protects them. A
// public_url that names the listener itself is direct mode whatever the list.
func challengeBehindProxy(cfg *config.Config) bool {
	return challengeHasTrustedProxy(cfg) && !challengePublicURLTargetsListener(cfg)
}

func challengeHasTrustedProxy(cfg *config.Config) bool {
	for _, p := range cfg.Challenge.TrustedProxies {
		if netutil.ParseCIDROrIP(p) != nil {
			return true
		}
	}
	return false
}

// A literal public endpoint can prove that browsers hit this listener
// directly. DNS names remain unverified rather than making network lookups
// a prerequisite for offline configuration checks.
func challengePublicURLTargetsListener(cfg *config.Config) bool {
	u, err := url.Parse(strings.TrimSpace(cfg.Challenge.PublicURL))
	if err != nil {
		return false
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	if port != strconv.Itoa(cfg.Challenge.ListenPort) {
		return false
	}
	publicIP := net.ParseIP(u.Hostname())
	listenIP := net.ParseIP(challenge.ListenHost(cfg.Challenge.ListenAddr))
	if publicIP == nil || listenIP == nil {
		return false
	}
	if listenIP.To4() != nil && publicIP.To4() == nil {
		return false
	}
	return listenIP.Equal(publicIP) || (listenIP.IsUnspecified() && netutil.IsHostAddress(publicIP.String()))
}

func defaultChallengeWebserverChecks(cfg *config.Config) []DoctorCheck {
	inst, err := webserver.New(platform.Detect(), cfg)
	if err != nil {
		status := "fail"
		fix := "inspect platform detection and install a supported Apache, LSWS, or Nginx stack"
		if errors.Is(err, webserver.ErrUnknownWebserver) {
			status = "warn"
			fix = "install webserver redirects manually or run on a supported Apache, LSWS, or Nginx stack"
		}
		return []DoctorCheck{{
			Name:    "challenge webserver",
			Status:  status,
			Message: err.Error(),
			Fix:     fix,
		}}
	}

	checks := make([]DoctorCheck, 0, 2)
	status, statusErr := inst.Status()
	checks = append(checks, challengeSnippetCheck(status, statusErr))
	validate, validateErr := inst.Validate()
	checks = append(checks, challengeConfigtestCheck(validate, validateErr))
	return checks
}

func challengeSnippetCheck(res webserver.Result, err error) DoctorCheck {
	if err != nil {
		return DoctorCheck{
			Name:    "challenge webserver snippet",
			Status:  "fail",
			Message: err.Error(),
			Fix:     "inspect the installed snippet path and webserver permissions",
		}
	}
	switch res.Status {
	case "ok":
		return DoctorCheck{Name: "challenge webserver snippet", Status: "ok", Message: res.Message}
	case "missing":
		return DoctorCheck{
			Name:    "challenge webserver snippet",
			Status:  "fail",
			Message: res.Message,
			Fix:     "run `csm webserver-integration install`",
		}
	default:
		return DoctorCheck{
			Name:    "challenge webserver snippet",
			Status:  "fail",
			Message: res.Message,
			Fix:     "run `csm webserver-integration upgrade` or inspect local edits",
		}
	}
}

func challengeConfigtestCheck(res webserver.Result, err error) DoctorCheck {
	if err != nil {
		return DoctorCheck{
			Name:    "challenge webserver configtest",
			Status:  "fail",
			Message: res.Message,
			Fix:     "fix the webserver configuration before reloading",
		}
	}
	return DoctorCheck{Name: "challenge webserver configtest", Status: "ok", Message: res.Message}
}

func defaultChallengeGateProbe(cfg *config.Config) DoctorCheck {
	rawURL, socketPath, err := challengeGateProbeTarget(cfg)
	if err != nil {
		return DoctorCheck{
			Name:    "challenge gate endpoint",
			Status:  "fail",
			Message: err.Error(),
			Fix:     "fix challenge.listen_addr and challenge.listen_port, then restart csm.service",
		}
	}
	client := &http.Client{Timeout: 2 * time.Second}
	target := rawURL
	if socketPath != "" {
		target = "unix:" + socketPath
		client.Transport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		}}
	}
	if strings.HasPrefix(rawURL, "https://") {
		// Fresh transport rather than cloning http.DefaultTransport: the
		// default may be wrapped (tracing, proxy) and the type assertion
		// would panic.
		client.Transport = &http.Transport{
			// #nosec G402 -- csm doctor probes the local listener for
			// reachability; it does not authenticate remote data or send
			// secrets.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	req, err := http.NewRequest(http.MethodHead, rawURL, nil)
	if err != nil {
		return DoctorCheck{Name: "challenge gate endpoint", Status: "fail", Message: err.Error()}
	}
	// Behind a trusted proxy the gate answers 400 unless a visitor is named,
	// so name a documentation address the way the proxy would. A peer that
	// is not a trusted proxy has the header ignored.
	req.Header.Set("X-Forwarded-For", "192.0.2.1")
	resp, err := client.Do(req)
	if err != nil {
		return DoctorCheck{
			Name:    "challenge gate endpoint",
			Status:  "fail",
			Message: err.Error(),
			Fix:     "start csm.service and confirm the challenge listener is bound and this user can open it",
		}
	}
	defer resp.Body.Close()
	// handleGate returns 204 when the probe IP is not currently challenged
	// and 401 when it is. Either response proves the handler is reachable
	// on the configured listener.
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusUnauthorized {
		return DoctorCheck{Name: "challenge gate endpoint", Status: "ok", Message: target}
	}
	return DoctorCheck{
		Name:    "challenge gate endpoint",
		Status:  "fail",
		Message: fmt.Sprintf("%s returned HTTP %d", target, resp.StatusCode),
		Fix:     "confirm the running daemon is serving /challenge/gate on the configured port",
	}
}

// challengeGateProbeTarget names the gate the doctor probes: a URL, plus the
// socket to dial when the listener is a Unix socket.
func challengeGateProbeTarget(cfg *config.Config) (rawURL, socketPath string, err error) {
	if path, socket := config.ChallengeSocketPath(cfg.Challenge.ListenAddr); socket {
		scheme := "http"
		if cert, key, _ := challengeRuntimeTLSMaterial(cfg); cert != "" && key != "" {
			scheme = "https"
		}
		return scheme + "://csm-challenge/challenge/gate", path, nil
	}
	rawURL, err = challengeGateProbeURL(cfg)
	return rawURL, "", err
}

func challengeGateProbeURL(cfg *config.Config) (string, error) {
	if cfg.Challenge.ListenPort <= 0 || cfg.Challenge.ListenPort > 65535 {
		return "", fmt.Errorf("invalid challenge.listen_port %d", cfg.Challenge.ListenPort)
	}
	host := challenge.ListenHost(cfg.Challenge.ListenAddr)
	switch host {
	case "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	scheme := "http"
	cert, key, _ := challengeRuntimeTLSMaterial(cfg)
	if cert != "" && key != "" {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(cfg.Challenge.ListenPort)) + "/challenge/gate", nil
}

func challengeListenAddrIsLoopbackDoctor(addr string) bool {
	ip := net.ParseIP(challenge.ListenHost(addr))
	return ip != nil && ip.IsLoopback()
}

// collapseDoctor reduces a slice of checks to the worst status seen:
// "fail" > "warn" > "ok".
func collapseDoctor(checks []DoctorCheck) string {
	worst := "ok"
	for _, c := range checks {
		switch c.Status {
		case "fail":
			return "fail"
		case "warn":
			worst = "warn"
		}
	}
	return worst
}

func emitDoctor(r DoctorReport, jsonOut bool) {
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
		if r.OverallStatus == "fail" {
			os.Exit(1)
		}
		return
	}
	fmt.Print(r.Human())
	if r.OverallStatus == "fail" {
		os.Exit(1)
	}
}

// Human renders the report as plain text.
func (r DoctorReport) Human() string {
	var b strings.Builder
	b.WriteString("=== csm doctor ===\n")
	for _, c := range r.Checks {
		var tag string
		switch c.Status {
		case "ok":
			tag = "[OK]   "
		case "warn":
			tag = "[WARN] "
		case "fail":
			tag = "[FAIL] "
		}
		fmt.Fprintf(&b, "%s%s\n", tag, c.Name)
		if c.Message != "" {
			fmt.Fprintf(&b, "       %s\n", c.Message)
		}
		if c.Fix != "" {
			fmt.Fprintf(&b, "       Fix: %s\n", c.Fix)
		}
	}
	fmt.Fprintf(&b, "\nOverall: %s\n", strings.ToUpper(r.OverallStatus))
	return b.String()
}
