package main

import (
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

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/integration/webserver"
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
	})
	emitDoctor(report, jsonOut)
}

func buildDoctorReport(loadConfig func() (*config.Config, error), readStatus func() ([]byte, error)) DoctorReport {
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
	report.Checks = append(report.Checks, DoctorCheck{Name: "config valid", Status: "ok"})
	_ = cfg

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

	report.OverallStatus = collapseDoctor(report.Checks)
	return report
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
			Fix:     "set challenge.public_url to an absolute http(s) URL ending in /challenge and bind challenge.listen_addr to a non-loopback address",
		}
	}
	return DoctorCheck{Name: "challenge public URL", Status: "ok"}
}

func challengeTLSCheck(cfg *config.Config) DoctorCheck {
	cert, key, source := challengeRuntimeTLSMaterial(cfg)
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
	if challengeListenAddrIsLoopbackDoctor(cfg.Challenge.ListenAddr) {
		return "", "", ""
	}
	if cfg.WebUI.TLSCert != "" || cfg.WebUI.TLSKey != "" {
		return cfg.WebUI.TLSCert, cfg.WebUI.TLSKey, "webui"
	}
	return "", "", ""
}

func challengePortGateCheck(cfg *config.Config) DoctorCheck {
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
		return DoctorCheck{
			Name:    "challenge port gate",
			Status:  "warn",
			Message: "public challenge listener is not protected by challenge.port_gate.enabled",
			Fix:     "set challenge.port_gate.enabled: true before exposing the listener broadly",
		}
	}
	return DoctorCheck{Name: "challenge port gate", Status: "ok"}
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
	rawURL, err := challengeGateProbeURL(cfg)
	if err != nil {
		return DoctorCheck{
			Name:    "challenge gate endpoint",
			Status:  "fail",
			Message: err.Error(),
			Fix:     "fix challenge.listen_addr and challenge.listen_port, then restart csm.service",
		}
	}
	client := &http.Client{Timeout: 2 * time.Second}
	if strings.HasPrefix(rawURL, "https://") {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		// #nosec G402 -- csm doctor probes the local listener for reachability;
		// it does not authenticate remote data or send secrets.
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		client.Transport = tr
	}
	req, err := http.NewRequest(http.MethodHead, rawURL, nil)
	if err != nil {
		return DoctorCheck{Name: "challenge gate endpoint", Status: "fail", Message: err.Error()}
	}
	resp, err := client.Do(req)
	if err != nil {
		return DoctorCheck{
			Name:    "challenge gate endpoint",
			Status:  "fail",
			Message: err.Error(),
			Fix:     "start csm.service and confirm the challenge listener is bound",
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusUnauthorized {
		return DoctorCheck{Name: "challenge gate endpoint", Status: "ok", Message: rawURL}
	}
	return DoctorCheck{
		Name:    "challenge gate endpoint",
		Status:  "fail",
		Message: fmt.Sprintf("%s returned HTTP %d", rawURL, resp.StatusCode),
		Fix:     "confirm the running daemon is serving /challenge/gate on the configured port",
	}
}

func challengeGateProbeURL(cfg *config.Config) (string, error) {
	if cfg.Challenge.ListenPort <= 0 || cfg.Challenge.ListenPort > 65535 {
		return "", fmt.Errorf("invalid challenge.listen_port %d", cfg.Challenge.ListenPort)
	}
	host := strings.TrimSpace(cfg.Challenge.ListenAddr)
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	default:
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if strings.EqualFold(host, "localhost") {
			host = "127.0.0.1"
		}
	}
	scheme := "http"
	cert, key, _ := challengeRuntimeTLSMaterial(cfg)
	if cert != "" && key != "" {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(cfg.Challenge.ListenPort)) + "/challenge/gate", nil
}

func challengeListenAddrIsLoopbackDoctor(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return true
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
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
