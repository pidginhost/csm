package checks

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// auditCmdTimeout is the per-subprocess timeout for audit checks.
// Audit checks are fast config reads, not heavy scans.
const auditCmdTimeout = 10 * time.Second

// RunHardeningAudit runs all hardening checks and returns a report.
// Pure function — reads system state only, no store access.
func RunHardeningAudit(cfg *config.Config) *store.AuditReport {
	serverType := detectServerType()

	var results []store.AuditResult
	results = append(results, auditSSH()...)
	results = append(results, auditPHP(serverType)...)
	results = append(results, auditWebServer(serverType)...)
	results = append(results, auditMail()...)
	if serverType != "bare" {
		results = append(results, auditCPanel(serverType)...)
	}
	results = append(results, auditOS()...)
	results = append(results, auditFirewall()...)

	score := 0
	for _, r := range results {
		if r.Status == "pass" {
			score++
		}
	}

	return &store.AuditReport{
		Timestamp:  time.Now(),
		ServerType: serverType,
		Results:    results,
		Score:      score,
		Total:      len(results),
	}
}

func detectServerType() string {
	if _, err := os.Stat("/usr/local/cpanel/version"); err == nil {
		if data, err := os.ReadFile("/etc/redhat-release"); err == nil {
			if strings.Contains(string(data), "CloudLinux") {
				return "cloudlinux"
			}
		}
		return "cpanel"
	}
	return "bare"
}

// auditRunCmd executes a command with the audit-specific timeout.
func auditRunCmd(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), auditCmdTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("command timed out: %s", name)
	}
	return out, err
}

// --- SSH checks ---

// sshdDefaults are the OpenSSH compiled defaults for settings we audit.
var sshdDefaults = map[string]string{
	"port":                    "22",
	"protocol":               "2",
	"passwordauthentication": "yes",
	"permitrootlogin":        "prohibit-password",
	"maxauthtries":           "6",
	"x11forwarding":          "no",
	"usedns":                 "no",
}

// parseSSHDConfig reads sshd_config + Include drop-ins with first-match-wins.
// Match blocks are skipped entirely (audit evaluates global config only).
func parseSSHDConfig() map[string]string {
	effective := make(map[string]string)
	parseSSHDFile("/etc/ssh/sshd_config", effective)
	return effective
}

func parseSSHDFile(path string, effective map[string]string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	inMatch := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Detect Match blocks — a Match block continues until the next
		// Match keyword or EOF, regardless of indentation (per sshd_config(5)).
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "match ") {
			inMatch = true
			continue
		}
		if inMatch {
			// Only another Match line (handled above) or EOF ends the block.
			// Everything else inside is a Match-scoped directive — skip it.
			continue
		}

		// Handle Include directives
		if strings.HasPrefix(lower, "include ") {
			pattern := strings.TrimSpace(line[8:])
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join("/etc/ssh", pattern)
			}
			matches, _ := filepath.Glob(pattern)
			for _, m := range matches {
				parseSSHDFile(m, effective)
			}
			continue
		}

		// Parse keyword=value or keyword value
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			parts = strings.SplitN(line, "=", 2)
		}
		if len(parts) < 2 {
			continue
		}
		keyword := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])

		// First-match-wins: only record the first occurrence
		if _, exists := effective[keyword]; !exists {
			effective[keyword] = value
		}
	}
}

func sshdEffective(parsed map[string]string, key string) string {
	if v, ok := parsed[key]; ok {
		return strings.ToLower(v)
	}
	return sshdDefaults[key]
}

func auditSSH() []store.AuditResult {
	parsed := parseSSHDConfig()
	var results []store.AuditResult

	// ssh_port
	port := sshdEffective(parsed, "port")
	if port == "22" {
		results = append(results, store.AuditResult{
			Category: "ssh", Name: "ssh_port", Title: "SSH Port",
			Status: "warn", Message: "SSH is running on default port 22",
			Fix: "Change to a non-standard port in /etc/ssh/sshd_config to reduce automated scan noise. Update firewall rules before changing.",
		})
	} else {
		results = append(results, store.AuditResult{
			Category: "ssh", Name: "ssh_port", Title: "SSH Port",
			Status: "pass", Message: fmt.Sprintf("SSH on non-standard port %s", port),
		})
	}

	// ssh_protocol
	proto := sshdEffective(parsed, "protocol")
	if strings.Contains(proto, "1") {
		results = append(results, store.AuditResult{
			Category: "ssh", Name: "ssh_protocol", Title: "SSH Protocol",
			Status: "fail", Message: "SSHv1 protocol is enabled",
			Fix: "Set 'Protocol 2' in /etc/ssh/sshd_config. SSHv1 has known cryptographic weaknesses.",
		})
	} else {
		results = append(results, store.AuditResult{
			Category: "ssh", Name: "ssh_protocol", Title: "SSH Protocol",
			Status: "pass", Message: "SSHv1 disabled",
		})
	}

	// ssh_password_auth
	passAuth := sshdEffective(parsed, "passwordauthentication")
	if passAuth != "no" {
		results = append(results, store.AuditResult{
			Category: "ssh", Name: "ssh_password_auth", Title: "SSH PasswordAuthentication",
			Status: "fail", Message: "Password authentication is enabled",
			Fix: "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config and use SSH key authentication only.",
		})
	} else {
		results = append(results, store.AuditResult{
			Category: "ssh", Name: "ssh_password_auth", Title: "SSH PasswordAuthentication",
			Status: "pass", Message: "Password authentication disabled",
		})
	}

	// ssh_root_login
	rootLogin := sshdEffective(parsed, "permitrootlogin")
	if rootLogin == "yes" {
		results = append(results, store.AuditResult{
			Category: "ssh", Name: "ssh_root_login", Title: "SSH PermitRootLogin",
			Status: "fail", Message: "Direct root login is permitted",
			Fix: "Set 'PermitRootLogin no' or 'PermitRootLogin prohibit-password' in /etc/ssh/sshd_config.",
		})
	} else {
		results = append(results, store.AuditResult{
			Category: "ssh", Name: "ssh_root_login", Title: "SSH PermitRootLogin",
			Status: "pass", Message: fmt.Sprintf("PermitRootLogin set to %s", rootLogin),
		})
	}

	// ssh_max_auth_tries
	maxTries := sshdEffective(parsed, "maxauthtries")
	n, _ := strconv.Atoi(maxTries)
	if n == 0 {
		n = 6 // default
	}
	if n > 4 {
		results = append(results, store.AuditResult{
			Category: "ssh", Name: "ssh_max_auth_tries", Title: "SSH MaxAuthTries",
			Status: "warn", Message: fmt.Sprintf("MaxAuthTries is %d (recommended: 4 or less)", n),
			Fix: "Set 'MaxAuthTries 4' in /etc/ssh/sshd_config to limit brute-force attempts per connection.",
		})
	} else {
		results = append(results, store.AuditResult{
			Category: "ssh", Name: "ssh_max_auth_tries", Title: "SSH MaxAuthTries",
			Status: "pass", Message: fmt.Sprintf("MaxAuthTries set to %d", n),
		})
	}

	// ssh_x11_forwarding
	x11 := sshdEffective(parsed, "x11forwarding")
	if x11 != "no" {
		results = append(results, store.AuditResult{
			Category: "ssh", Name: "ssh_x11_forwarding", Title: "SSH X11Forwarding",
			Status: "warn", Message: "X11 forwarding is enabled",
			Fix: "Set 'X11Forwarding no' in /etc/ssh/sshd_config unless X11 forwarding is actively needed.",
		})
	} else {
		results = append(results, store.AuditResult{
			Category: "ssh", Name: "ssh_x11_forwarding", Title: "SSH X11Forwarding",
			Status: "pass", Message: "X11 forwarding disabled",
		})
	}

	// ssh_use_dns
	useDNS := sshdEffective(parsed, "usedns")
	if useDNS != "no" {
		results = append(results, store.AuditResult{
			Category: "ssh", Name: "ssh_use_dns", Title: "SSH UseDNS",
			Status: "warn", Message: "UseDNS is enabled",
			Fix: "Set 'UseDNS no' in /etc/ssh/sshd_config. Otherwise lfd may not track SSH login failures by IP.",
		})
	} else {
		results = append(results, store.AuditResult{
			Category: "ssh", Name: "ssh_use_dns", Title: "SSH UseDNS",
			Status: "pass", Message: "UseDNS disabled",
		})
	}

	return results
}

// Stubs for remaining categories — implemented in subsequent tasks.

func auditPHP(_ string) []store.AuditResult       { return nil }
func auditWebServer(_ string) []store.AuditResult  { return nil }
func auditMail() []store.AuditResult               { return nil }
func auditCPanel(_ string) []store.AuditResult     { return nil }
func auditOS() []store.AuditResult                 { return nil }
func auditFirewall() []store.AuditResult           { return nil }
