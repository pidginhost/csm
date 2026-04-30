package checks

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
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
	info := platform.Detect()
	if info.IsCPanel() {
		if info.OS == platform.OSCloudLinux {
			return "cloudlinux"
		}
		return "cpanel"
	}
	return "bare"
}

// auditRunCmd executes a command with the audit-specific timeout via the
// cmdExec injector so tests can mock systemctl/cagefsctl/etc. without
// invoking real binaries on the host.
func auditRunCmd(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), auditCmdTimeout)
	defer cancel()
	out, err := cmdExec.RunContext(ctx, name, args...)
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("command timed out: %s", name)
	}
	return out, err
}

// --- SSH checks ---

// sshdDefaults are the OpenSSH compiled defaults for settings we audit.
var sshdDefaults = map[string]string{
	"port":                   "22",
	"protocol":               "2",
	"passwordauthentication": "yes",
	"permitrootlogin":        "prohibit-password",
	"maxauthtries":           "6",
	"x11forwarding":          "no",
	"usedns":                 "no",
}

var sshdConfigPath = "/etc/ssh/sshd_config"

type sshdSettings struct {
	PasswordAuthentication string
	PermitRootLogin        string
	X11Forwarding          string
}

// parseSSHDConfig reads sshd_config + Include drop-ins with first-match-wins.
// Match blocks are skipped entirely (audit evaluates global config only).
func parseSSHDConfig() map[string]string {
	effective := make(map[string]string)
	parseSSHDFile(sshdConfigPath, effective)
	return effective
}

func parseSSHDFile(path string, effective map[string]string) {
	f, err := osFS.Open(path)
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
				pattern = filepath.Join(filepath.Dir(path), pattern)
			}
			matches, _ := osFS.Glob(pattern)
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

func currentSSHDSettings() sshdSettings {
	parsed := parseSSHDConfig()
	return sshdSettings{
		PasswordAuthentication: sshdEffective(parsed, "passwordauthentication"),
		PermitRootLogin:        sshdEffective(parsed, "permitrootlogin"),
		X11Forwarding:          sshdEffective(parsed, "x11forwarding"),
	}
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

// --- OS hardening checks ---

func auditOS() []store.AuditResult {
	var results []store.AuditResult

	// /tmp and /var/tmp permissions
	for _, dir := range []struct {
		path, id, title string
	}{
		{"/tmp", "os_tmp_permissions", "/tmp Permissions"},
		{"/var/tmp", "os_var_tmp_permissions", "/var/tmp Permissions"},
	} {
		info, err := osFS.Stat(dir.path)
		if err != nil {
			results = append(results, store.AuditResult{
				Category: "os", Name: dir.id, Title: dir.title,
				Status: "warn", Message: fmt.Sprintf("Cannot stat %s: %v", dir.path, err),
			})
			continue
		}
		// Use the raw Unix mode bits from syscall to get the traditional
		// permission representation (sticky=01000, setuid=04000, etc.).
		// Go's os.ModeSticky uses high bits that don't map to Unix octal,
		// so os.FileMode math produces wrong values for comparison.
		// Only check the lower 12 bits (sticky + rwx) — ignore setuid/setgid
		// which CloudLinux/CageFS may set on virtmp mounts.
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			results = append(results, store.AuditResult{
				Category: "os", Name: dir.id, Title: dir.title,
				Status: "warn", Message: fmt.Sprintf("Cannot read ownership of %s", dir.path),
			})
			continue
		}
		mode := stat.Mode & 01777 // sticky + rwxrwxrwx, ignore setuid/setgid
		if mode != 01777 || stat.Uid != 0 || stat.Gid != 0 {
			results = append(results, store.AuditResult{
				Category: "os", Name: dir.id, Title: dir.title,
				Status:  "fail",
				Message: fmt.Sprintf("%s has mode %04o uid=%d gid=%d (expected 1777 root:root)", dir.path, mode, stat.Uid, stat.Gid),
				Fix:     fmt.Sprintf("chmod 1777 %s && chown root:root %s", dir.path, dir.path),
			})
		} else {
			results = append(results, store.AuditResult{
				Category: "os", Name: dir.id, Title: dir.title,
				Status: "pass", Message: fmt.Sprintf("%s is 1777 root:root", dir.path),
			})
		}
	}

	// /etc/shadow permissions
	// Accept 0000, 0600 (RHEL/CentOS default), and 0640 (Debian default).
	// All three restrict access to root only. 0600 is the standard on
	// CentOS/CloudLinux — changing it can break passwd/chage.
	if info, err := osFS.Stat("/etc/shadow"); err == nil {
		perm := info.Mode().Perm()
		if perm == 0 || perm == 0o600 || perm == 0o640 {
			results = append(results, store.AuditResult{
				Category: "os", Name: "os_shadow_permissions", Title: "/etc/shadow Permissions",
				Status: "pass", Message: fmt.Sprintf("/etc/shadow has mode %04o", perm),
			})
		} else {
			results = append(results, store.AuditResult{
				Category: "os", Name: "os_shadow_permissions", Title: "/etc/shadow Permissions",
				Status: "fail", Message: fmt.Sprintf("/etc/shadow has mode %04o (expected 0000, 0600, or 0640)", perm),
				Fix: "chmod 0600 /etc/shadow",
			})
		}
	} else {
		results = append(results, store.AuditResult{
			Category: "os", Name: "os_shadow_permissions", Title: "/etc/shadow Permissions",
			Status: "warn", Message: "Cannot stat /etc/shadow",
		})
	}

	// Swap
	if data, err := osFS.ReadFile("/proc/swaps"); err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) > 1 {
			results = append(results, store.AuditResult{
				Category: "os", Name: "os_swap", Title: "Swap Configured",
				Status: "pass", Message: fmt.Sprintf("%d swap device(s) active", len(lines)-1),
			})
		} else {
			results = append(results, store.AuditResult{
				Category: "os", Name: "os_swap", Title: "Swap Configured",
				Status: "warn", Message: "No swap configured",
				Fix: "Configure swap space to prevent OOM kills: fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile",
			})
		}
	}

	// Distro EOL
	results = append(results, checkDistroEOL()...)

	// nobody crontab
	if info, err := osFS.Stat("/var/spool/cron/nobody"); err != nil {
		// absent is fine
		results = append(results, store.AuditResult{
			Category: "os", Name: "os_nobody_cron", Title: "Nobody Crontab",
			Status: "pass", Message: "No crontab for nobody user",
		})
	} else if info.Size() == 0 {
		results = append(results, store.AuditResult{
			Category: "os", Name: "os_nobody_cron", Title: "Nobody Crontab",
			Status: "pass", Message: "Nobody crontab is empty",
		})
	} else {
		results = append(results, store.AuditResult{
			Category: "os", Name: "os_nobody_cron", Title: "Nobody Crontab",
			Status: "fail", Message: "nobody user has a crontab with content",
			Fix: "Review and remove: crontab -u nobody -r",
		})
	}

	// Unnecessary services
	results = append(results, checkUnnecessaryServices()...)

	// Sysctl checks (table-driven)
	sysctlChecks := []struct {
		id, title, path, expected string
	}{
		{"os_sysctl_syncookies", "TCP SYN Cookies", "/proc/sys/net/ipv4/tcp_syncookies", "1"},
		{"os_sysctl_aslr", "Address Space Layout Randomization", "/proc/sys/kernel/randomize_va_space", "2"},
		{"os_sysctl_rp_filter", "Reverse Path Filtering", "/proc/sys/net/ipv4/conf/all/rp_filter", "1"},
		{"os_sysctl_icmp_broadcast", "ICMP Broadcast Ignore", "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts", "1"},
		{"os_sysctl_symlinks", "Protected Symlinks", "/proc/sys/fs/protected_symlinks", "1"},
		{"os_sysctl_hardlinks", "Protected Hardlinks", "/proc/sys/fs/protected_hardlinks", "1"},
	}
	for _, sc := range sysctlChecks {
		data, err := osFS.ReadFile(sc.path)
		if err != nil {
			results = append(results, store.AuditResult{
				Category: "os", Name: sc.id, Title: sc.title,
				Status: "warn", Message: fmt.Sprintf("Cannot read %s", sc.path),
			})
			continue
		}
		val := strings.TrimSpace(string(data))
		// Convert /proc/sys path to sysctl dotted notation for fix command
		sysctlKey := strings.TrimPrefix(sc.path, "/proc/sys/")
		sysctlKey = strings.ReplaceAll(sysctlKey, "/", ".")
		if val == sc.expected {
			results = append(results, store.AuditResult{
				Category: "os", Name: sc.id, Title: sc.title,
				Status: "pass", Message: fmt.Sprintf("%s = %s", sysctlKey, val),
			})
		} else {
			results = append(results, store.AuditResult{
				Category: "os", Name: sc.id, Title: sc.title,
				Status: "fail", Message: fmt.Sprintf("%s = %s (expected %s)", sysctlKey, val, sc.expected),
				Fix: fmt.Sprintf("sysctl -w %s=%s && echo '%s = %s' >> /etc/sysctl.d/99-csm-hardening.conf", sysctlKey, sc.expected, sysctlKey, sc.expected),
			})
		}
	}

	return results
}

// algifAEADBlacklisted reports whether any of the supplied modprobe.d files
// contain a non-comment directive that prevents algif_aead from loading.
// The two recognised forms are:
//
//	blacklist algif_aead
//	install algif_aead /bin/false   (or any non-loading replacement)
//
// `install algif_aead /sbin/modprobe --ignore-install algif_aead` is the
// idiomatic re-load form and explicitly does NOT block the module — we
// detect that by skipping any install replacement that calls modprobe.
func algifAEADBlacklisted(confs map[string]string) bool {
	for _, body := range confs {
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[1] != "algif_aead" {
				continue
			}
			switch fields[0] {
			case "blacklist":
				return true
			case "install":
				if len(fields) < 3 {
					// Malformed (no replacement command). Don't claim a
					// pass on a half-written directive.
					continue
				}
				// Match on the basename of the first token, not a substring
				// anywhere in the line. That correctly classifies
				//   /sbin/modprobe --ignore-install algif_aead   → re-load
				//   /bin/false                                   → block
				//   /usr/local/bin/my-modprobe-wrapper           → block (wrapper, not modprobe itself)
				// Substring matching would have lumped the wrapper case in
				// with the re-load case, producing a false-fail alert.
				if filepath.Base(fields[2]) == "modprobe" {
					continue
				}
				return true
			}
		}
	}
	return false
}

// evaluateAlgifAEAD is the pure, testable core of the algif_aead hardening
// check. `loaded` reports whether algif_aead currently shows up in
// /proc/modules; `confs` is a map of modprobe.d file path → contents.
func evaluateAlgifAEAD(loaded bool, confs map[string]string) store.AuditResult {
	const (
		id    = "os_algif_aead_blocked"
		title = "AF_ALG (algif_aead) Blocked — CVE-2026-31431"
	)
	blocked := algifAEADBlacklisted(confs)
	switch {
	case !loaded && blocked:
		return store.AuditResult{
			Category: "os", Name: id, Title: title,
			Status: "pass", Message: "algif_aead is blacklisted and not loaded",
		}
	case loaded:
		return store.AuditResult{
			Category: "os", Name: id, Title: title,
			Status:  "fail",
			Message: "algif_aead is currently loaded — Copy Fail (CVE-2026-31431) exploitable",
			Fix:     "echo 'install algif_aead /bin/false' > /etc/modprobe.d/csm-disable-algif.conf && modprobe -r algif_aead af_alg",
		}
	default:
		return store.AuditResult{
			Category: "os", Name: id, Title: title,
			Status:  "fail",
			Message: "algif_aead is not loaded but no modprobe.d blacklist exists — module can be loaded on demand",
			Fix:     "echo 'install algif_aead /bin/false' > /etc/modprobe.d/csm-disable-algif.conf",
		}
	}
}

// distroEOLPolicy encodes the oldest supported major version per known OS.
// Anything below the minimum is considered EOL by this check.
var distroEOLPolicy = map[platform.OSFamily]int{
	platform.OSAlma:       8,
	platform.OSRocky:      8,
	platform.OSRHEL:       8,
	platform.OSCloudLinux: 7,
	platform.OSUbuntu:     20, // 20.04 is the oldest non-EOL LTS
	platform.OSDebian:     11, // Debian 11 "bullseye"
}

func checkDistroEOL() []store.AuditResult {
	return evaluateDistroEOL(platform.Detect(), readOSReleasePretty())
}

// evaluateDistroEOL is the pure, testable core of checkDistroEOL. It returns
// an AuditResult based purely on the supplied platform info and
// PRETTY_NAME string (either may be empty).
func evaluateDistroEOL(info platform.Info, prettyName string) []store.AuditResult {
	if prettyName == "" && info.OSVersion != "" {
		prettyName = fmt.Sprintf("%s %s", info.OS, info.OSVersion)
	}

	if info.OS == platform.OSUnknown || info.OSVersion == "" {
		return []store.AuditResult{{
			Category: "os", Name: "os_distro_eol", Title: "Distribution End of Life",
			Status: "warn", Message: "Unable to determine distribution version",
		}}
	}

	if info.OS == platform.OSCentOS {
		return []store.AuditResult{{
			Category: "os", Name: "os_distro_eol", Title: "Distribution End of Life",
			Status:  "fail",
			Message: fmt.Sprintf("%s — CentOS is end-of-life", prettyName),
			Fix:     "Migrate to a supported replacement such as AlmaLinux, Rocky Linux, or RHEL. CentOS no longer receives security patches.",
		}}
	}

	// Extract the major version. Ubuntu/Debian use "24.04" / "12", RHEL
	// family uses "8.6" / "10", etc. Taking the integer prefix handles both.
	majorStr, _, _ := strings.Cut(info.OSVersion, ".")
	major, err := strconv.Atoi(majorStr)
	if err != nil {
		return []store.AuditResult{{
			Category: "os", Name: "os_distro_eol", Title: "Distribution End of Life",
			Status: "warn", Message: fmt.Sprintf("%s — unable to parse version %q", prettyName, info.OSVersion),
		}}
	}

	minVersion, known := distroEOLPolicy[info.OS]
	if !known {
		return []store.AuditResult{{
			Category: "os", Name: "os_distro_eol", Title: "Distribution End of Life",
			Status: "warn", Message: fmt.Sprintf("%s — no EOL policy configured for this distro", prettyName),
		}}
	}

	if major < minVersion {
		fix := "Upgrade to a supported release. EOL distributions receive no security patches."
		if info.IsRHELFamily() {
			fix = fmt.Sprintf("Upgrade to %s %d+ or newer. EOL distributions receive no security patches.", info.OS, minVersion)
		}
		if info.IsDebianFamily() {
			fix = fmt.Sprintf("Upgrade to %s %d+ or newer LTS. EOL distributions receive no security patches.", info.OS, minVersion)
		}
		return []store.AuditResult{{
			Category: "os", Name: "os_distro_eol", Title: "Distribution End of Life",
			Status:  "fail",
			Message: fmt.Sprintf("%s — major version %d is EOL", prettyName, major),
			Fix:     fix,
		}}
	}

	return []store.AuditResult{{
		Category: "os", Name: "os_distro_eol", Title: "Distribution End of Life",
		Status: "pass", Message: prettyName,
	}}
}

// readOSReleasePretty returns the PRETTY_NAME from /etc/os-release or "".
func readOSReleasePretty() string {
	data, err := osFS.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"'`)
		}
	}
	return ""
}

func checkUnnecessaryServices() []store.AuditResult {
	badServices := []string{
		"avahi-daemon", "bluetooth", "cups", "cupsd", "gdm",
		"ModemManager", "packagekit", "rpcbind", "wpa_supplicant", "firewalld",
	}

	out, err := auditRunCmd("systemctl", "list-unit-files", "--state=enabled", "--no-pager", "--no-legend")
	if err != nil {
		return []store.AuditResult{{
			Category: "os", Name: "os_services", Title: "Unnecessary Services",
			Status: "warn", Message: "Cannot query systemd unit files",
		}}
	}

	var found []string
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		unit := strings.TrimSuffix(fields[0], ".service")
		for _, bad := range badServices {
			if unit == bad {
				found = append(found, bad)
			}
		}
	}

	if len(found) == 0 {
		return []store.AuditResult{{
			Category: "os", Name: "os_services", Title: "Unnecessary Services",
			Status: "pass", Message: "No unnecessary services enabled",
		}}
	}
	return []store.AuditResult{{
		Category: "os", Name: "os_services", Title: "Unnecessary Services",
		Status:  "warn",
		Message: fmt.Sprintf("Unnecessary services enabled: %s", strings.Join(found, ", ")),
		Fix:     fmt.Sprintf("systemctl disable --now %s", strings.Join(found, " ")),
	}}
}

// --- Firewall checks ---

func auditFirewall() []store.AuditResult {
	var results []store.AuditResult

	// Gather nft and iptables state
	nftOut, nftErr := auditRunCmd("nft", "list", "ruleset")
	nftRules := string(nftOut)
	hasNft := nftErr == nil && strings.TrimSpace(nftRules) != ""

	iptOut, iptErr := auditRunCmd("iptables", "-L", "INPUT", "-n")
	iptRules := string(iptOut)
	hasIpt := iptErr == nil && strings.TrimSpace(iptRules) != ""

	// fw_active
	if hasNft || hasIpt {
		results = append(results, store.AuditResult{
			Category: "firewall", Name: "fw_active", Title: "Firewall Active",
			Status: "pass", Message: "Firewall has active rules",
		})
	} else {
		results = append(results, store.AuditResult{
			Category: "firewall", Name: "fw_active", Title: "Firewall Active",
			Status: "fail", Message: "No active firewall rules detected",
			Fix: "Install and configure nftables or iptables with a default-deny policy.",
		})
	}

	// fw_default_policy
	defaultDeny := false
	if hasNft {
		lower := strings.ToLower(nftRules)
		if strings.Contains(lower, "policy drop") || strings.Contains(lower, "policy reject") {
			defaultDeny = true
		}
	}
	if !defaultDeny && hasIpt {
		for _, line := range strings.Split(iptRules, "\n") {
			if strings.HasPrefix(line, "Chain INPUT") {
				upper := strings.ToUpper(line)
				if strings.Contains(upper, "POLICY DROP") || strings.Contains(upper, "POLICY REJECT") {
					defaultDeny = true
				}
				break
			}
		}
	}
	if defaultDeny {
		results = append(results, store.AuditResult{
			Category: "firewall", Name: "fw_default_policy", Title: "Default INPUT Policy",
			Status: "pass", Message: "INPUT chain has default-deny policy",
		})
	} else {
		results = append(results, store.AuditResult{
			Category: "firewall", Name: "fw_default_policy", Title: "Default INPUT Policy",
			Status: "fail", Message: "INPUT chain does not have a DROP/REJECT policy",
			Fix: "Set the default INPUT policy to DROP: iptables -P INPUT DROP (or nft equivalent).",
		})
	}

	// fw_mysql_exposed
	results = append(results, checkMySQLExposed(hasNft, nftRules, hasIpt, iptRules)...)

	// fw_telnet
	if isPortListening(23) {
		results = append(results, store.AuditResult{
			Category: "firewall", Name: "fw_telnet", Title: "Telnet Service",
			Status: "fail", Message: "Something is listening on port 23 (telnet)",
			Fix: "Disable telnet: systemctl disable --now telnet.socket xinetd; use SSH instead.",
		})
	} else {
		results = append(results, store.AuditResult{
			Category: "firewall", Name: "fw_telnet", Title: "Telnet Service",
			Status: "pass", Message: "Nothing listening on port 23",
		})
	}

	// fw_ipv6
	results = append(results, checkIPv6Firewall()...)

	return results
}

// getListeningAddr reads /proc/net/tcp for a port in LISTEN state (0A)
// and returns the hex-encoded local IP, or "" if not found.
func getListeningAddr(port int) string {
	hexPort := fmt.Sprintf("%04X", port)
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := osFS.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			// fields[1] = local_address (hex_ip:hex_port), fields[3] = state
			if fields[3] != "0A" { // 0A = LISTEN
				continue
			}
			parts := strings.SplitN(fields[1], ":", 2)
			if len(parts) != 2 {
				continue
			}
			if parts[1] == hexPort {
				return parts[0]
			}
		}
	}
	return ""
}

// hexToIPv4 converts a /proc/net/tcp hex IP (little-endian 32-bit) to dotted notation.
func hexToIPv4(h string) string {
	if len(h) != 8 {
		return h
	}
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 4 {
		return h
	}
	// /proc/net/tcp stores IPs in little-endian byte order
	return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
}

// isPrivateOrLoopback returns true for loopback, RFC1918, and RFC4193 addresses.
func isPrivateOrLoopback(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	// Check private ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
	}
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// isPortListening checks /proc/net/tcp and /proc/net/tcp6 for a port in LISTEN state.
func isPortListening(port int) bool {
	hexPort := fmt.Sprintf("%04X", port)
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := osFS.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			if fields[3] != "0A" {
				continue
			}
			parts := strings.SplitN(fields[1], ":", 2)
			if len(parts) == 2 && parts[1] == hexPort {
				return true
			}
		}
	}
	return false
}

func checkMySQLExposed(hasNft bool, nftRules string, hasIpt bool, iptRules string) []store.AuditResult {
	hexAddr := getListeningAddr(3306)
	if hexAddr == "" {
		return []store.AuditResult{{
			Category: "firewall", Name: "fw_mysql_exposed", Title: "MySQL Exposure",
			Status: "pass", Message: "MySQL is not listening on any port",
		}}
	}

	// Convert hex addr to IP and check if private/loopback
	var ip string
	if len(hexAddr) == 8 {
		ip = hexToIPv4(hexAddr)
	} else {
		// IPv6: 32 hex chars, little-endian 4-byte groups
		if b, err := hex.DecodeString(hexAddr); err == nil {
			ipBytes := make(net.IP, len(b))
			// Reverse each 4-byte group for /proc/net/tcp6 little-endian encoding
			for i := 0; i+4 <= len(b); i += 4 {
				ipBytes[i] = b[i+3]
				ipBytes[i+1] = b[i+2]
				ipBytes[i+2] = b[i+1]
				ipBytes[i+3] = b[i]
			}
			ip = ipBytes.String()
		}
	}

	// All zeros = wildcard bind
	allZero := true
	for _, c := range hexAddr {
		if c != '0' {
			allZero = false
			break
		}
	}

	if !allZero && ip != "" && isPrivateOrLoopback(ip) {
		return []store.AuditResult{{
			Category: "firewall", Name: "fw_mysql_exposed", Title: "MySQL Exposure",
			Status: "pass", Message: fmt.Sprintf("MySQL bound to private/loopback address %s", ip),
		}}
	}

	// Wildcard or public bind — check if firewall blocks 3306
	fwBlocks3306 := false
	if hasNft && !strings.Contains(nftRules, "3306") {
		// If nft has rules but doesn't mention 3306 and has default deny, it's blocked
		lower := strings.ToLower(nftRules)
		if strings.Contains(lower, "policy drop") || strings.Contains(lower, "policy reject") {
			fwBlocks3306 = true
		}
	}
	if !fwBlocks3306 && hasIpt && !strings.Contains(iptRules, "3306") {
		for _, line := range strings.Split(iptRules, "\n") {
			if strings.HasPrefix(line, "Chain INPUT") {
				upper := strings.ToUpper(line)
				if strings.Contains(upper, "POLICY DROP") || strings.Contains(upper, "POLICY REJECT") {
					fwBlocks3306 = true
				}
				break
			}
		}
	}

	bindDesc := "wildcard (0.0.0.0)"
	if !allZero && ip != "" {
		bindDesc = ip
	}

	if fwBlocks3306 {
		return []store.AuditResult{{
			Category: "firewall", Name: "fw_mysql_exposed", Title: "MySQL Exposure",
			Status:  "warn",
			Message: fmt.Sprintf("MySQL bound to %s but firewall blocks port 3306", bindDesc),
			Fix:     "Bind MySQL to 127.0.0.1 in /etc/my.cnf: bind-address = 127.0.0.1",
		}}
	}

	return []store.AuditResult{{
		Category: "firewall", Name: "fw_mysql_exposed", Title: "MySQL Exposure",
		Status:  "fail",
		Message: fmt.Sprintf("MySQL bound to %s and port 3306 appears accessible", bindDesc),
		Fix:     "Bind MySQL to 127.0.0.1 in /etc/my.cnf and/or block port 3306 in firewall.",
	}}
}

func checkIPv6Firewall() []store.AuditResult {
	// Check if any non-loopback, non-link-local IPv6 addresses exist
	data, err := osFS.ReadFile("/proc/net/if_inet6")
	if err != nil {
		return []store.AuditResult{{
			Category: "firewall", Name: "fw_ipv6", Title: "IPv6 Firewall",
			Status: "pass", Message: "IPv6 not active (cannot read /proc/net/if_inet6)",
		}}
	}

	hasIPv6 := false
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		addr := fields[0]
		iface := fields[5]
		// Skip loopback
		if iface == "lo" {
			continue
		}
		// Skip link-local (fe80::/10)
		if strings.HasPrefix(strings.ToLower(addr), "fe80") {
			continue
		}
		hasIPv6 = true
		break
	}

	if !hasIPv6 {
		return []store.AuditResult{{
			Category: "firewall", Name: "fw_ipv6", Title: "IPv6 Firewall",
			Status: "pass", Message: "No non-link-local IPv6 addresses found",
		}}
	}

	// Check nftables for inet/ip6 family chain with input hook and default deny
	nftChains, err := auditRunCmd("nft", "list", "chains")
	if err == nil {
		chainsStr := strings.ToLower(string(nftChains))
		// Look for chains in inet or ip6 family with filter hook input
		// nft list chains output looks like:
		// table inet filter {
		//   chain input {
		//     type filter hook input priority filter; policy drop;
		//   }
		// }
		var currentFamily string
		for _, line := range strings.Split(chainsStr, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "table ") {
				parts := strings.Fields(trimmed)
				if len(parts) >= 3 {
					currentFamily = parts[1]
				}
			}
			if (currentFamily == "inet" || currentFamily == "ip6") &&
				strings.Contains(trimmed, "hook input") {
				if strings.Contains(trimmed, "policy drop") || strings.Contains(trimmed, "policy reject") {
					return []store.AuditResult{{
						Category: "firewall", Name: "fw_ipv6", Title: "IPv6 Firewall",
						Status: "pass", Message: fmt.Sprintf("IPv6 active; nftables %s family has default-deny input chain", currentFamily),
					}}
				}
			}
		}
	}

	// Fallback: check ip6tables
	ip6Out, err := auditRunCmd("ip6tables", "-L", "INPUT", "-n")
	if err == nil {
		for _, line := range strings.Split(string(ip6Out), "\n") {
			if strings.HasPrefix(line, "Chain INPUT") {
				upper := strings.ToUpper(line)
				if strings.Contains(upper, "POLICY DROP") || strings.Contains(upper, "POLICY REJECT") {
					return []store.AuditResult{{
						Category: "firewall", Name: "fw_ipv6", Title: "IPv6 Firewall",
						Status: "pass", Message: "IPv6 active; ip6tables INPUT chain has default-deny policy",
					}}
				}
				break
			}
		}
	}

	return []store.AuditResult{{
		Category: "firewall", Name: "fw_ipv6", Title: "IPv6 Firewall",
		Status: "fail", Message: "IPv6 is active but no default-deny input policy found",
		Fix: "Configure ip6tables or nftables inet family with a default DROP policy for INPUT.",
	}}
}

// --- cPanel/WHM and CloudLinux checks ---

func auditCPanel(serverType string) []store.AuditResult {
	var results []store.AuditResult

	cpConf := parseCpanelConfig("/var/cpanel/cpanel.config")

	// Table-driven boolean checks on cpanel.config.
	// fix is the human-readable remediation shown in the UI.
	type cpCheck struct {
		id, title, key, wantVal string
		invert                  bool // true = fail when value matches wantVal
		fix                     string
	}
	checks := []cpCheck{
		{"cp_ssl_only", "Always Redirect to SSL", "alwaysredirecttossl", "1", false,
			"In WHM > Tweak Settings > Redirection, set 'Always redirect to SSL/TLS' to On."},
		{"cp_boxtrapper", "BoxTrapper Disabled", "skipboxtrapper", "1", false,
			"In WHM > Tweak Settings > Mail, set 'Enable BoxTrapper spam trap' to Off."},
		{"cp_password_reset", "Password Reset Disabled", "resetpass", "1", true,
			"In WHM > Tweak Settings > System, set 'Reset Password for cPanel accounts' to Off."},
		{"cp_password_reset_sub", "Subaccount Password Reset Disabled", "resetpass_sub", "1", true,
			"In WHM > Tweak Settings > System, set 'Reset Password for Subaccounts' to Off."},
		{"cp_email_passwords", "Email Passwords Disabled", "emailpasswords", "1", true,
			"In WHM > Tweak Settings > Security, set 'Send passwords when creating a new account' to Off."},
		{"cp_cookie_validation", "Cookie IP Validation", "cookieipvalidation", "strict", false,
			"In WHM > Tweak Settings > Security, set 'Cookie IP validation' to strict."},
		{"cp_remote_domains", "Remote Domains Disabled", "allowremotedomains", "1", true,
			"In WHM > Tweak Settings > Domains, set 'Allow Remote Domains' to Off."},
		{"cp_core_dumps", "Core Dumps Disabled", "coredump", "1", true,
			"In WHM > Tweak Settings > Security, set 'Generate core dumps' to Off."},
		{"cp_nobodyspam", "Nobody Spam Prevention", "nobodyspam", "1", false,
			"In WHM > Tweak Settings > Mail, set 'Prevent nobody from sending mail' to On."},
	}

	for _, c := range checks {
		val := cpConf[c.key]
		var pass bool
		if c.invert {
			pass = val != c.wantVal
		} else {
			pass = val == c.wantVal
		}
		if pass {
			results = append(results, store.AuditResult{
				Category: "cpanel", Name: c.id, Title: c.title,
				Status: "pass", Message: fmt.Sprintf("%s = %s", c.key, val),
			})
		} else {
			results = append(results, store.AuditResult{
				Category: "cpanel", Name: c.id, Title: c.title,
				Status: "fail", Message: fmt.Sprintf("%s = %s", c.key, val),
				Fix: c.fix,
			})
		}
	}

	// cp_max_emails_hour
	maxEmail := cpConf["maxemailsperhour"]
	if maxEmail != "" && maxEmail != "0" {
		results = append(results, store.AuditResult{
			Category: "cpanel", Name: "cp_max_emails_hour", Title: "Max Emails Per Hour",
			Status: "pass", Message: fmt.Sprintf("maxemailsperhour = %s", maxEmail),
		})
	} else {
		results = append(results, store.AuditResult{
			Category: "cpanel", Name: "cp_max_emails_hour", Title: "Max Emails Per Hour",
			Status: "fail", Message: "maxemailsperhour is not set or is 0",
			Fix: "In WHM > Tweak Settings, set 'Max emails per hour per domain' to a reasonable limit (e.g., 200).",
		})
	}

	// cp_compilers: check /usr/bin/cc permissions
	if info, err := osFS.Stat("/usr/bin/cc"); err == nil {
		perm := info.Mode().Perm()
		if perm <= 0o750 {
			results = append(results, store.AuditResult{
				Category: "cpanel", Name: "cp_compilers", Title: "Compiler Access Restricted",
				Status: "pass", Message: fmt.Sprintf("/usr/bin/cc has mode %04o", perm),
			})
		} else {
			results = append(results, store.AuditResult{
				Category: "cpanel", Name: "cp_compilers", Title: "Compiler Access Restricted",
				Status: "fail", Message: fmt.Sprintf("/usr/bin/cc has mode %04o (should be <= 0750)", perm),
				Fix: "WHM > Security Center > Compiler Access, or: chmod 750 /usr/bin/cc",
			})
		}
	} else {
		results = append(results, store.AuditResult{
			Category: "cpanel", Name: "cp_compilers", Title: "Compiler Access Restricted",
			Status: "pass", Message: "No compiler found at /usr/bin/cc",
		})
	}

	// cp_ftp_anonymous: parse /etc/pure-ftpd.conf
	if data, err := osFS.ReadFile("/etc/pure-ftpd.conf"); err == nil {
		noAnon := false
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.HasPrefix(trimmed, "NoAnonymous") {
				parts := strings.Fields(trimmed)
				if len(parts) >= 2 && strings.EqualFold(parts[1], "yes") {
					noAnon = true
				}
			}
		}
		if noAnon {
			results = append(results, store.AuditResult{
				Category: "cpanel", Name: "cp_ftp_anonymous", Title: "Anonymous FTP Disabled",
				Status: "pass", Message: "NoAnonymous is enabled in pure-ftpd",
			})
		} else {
			results = append(results, store.AuditResult{
				Category: "cpanel", Name: "cp_ftp_anonymous", Title: "Anonymous FTP Disabled",
				Status: "fail", Message: "Anonymous FTP may be enabled",
				Fix: "Set 'NoAnonymous yes' in /etc/pure-ftpd.conf and restart pure-ftpd.",
			})
		}
	}

	// cp_updates: parse /etc/cpupdate.conf
	if data, err := osFS.ReadFile("/etc/cpupdate.conf"); err == nil {
		updatesDaily := false
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.HasPrefix(strings.ToUpper(trimmed), "UPDATES=") {
				val := strings.TrimPrefix(trimmed, trimmed[:strings.Index(trimmed, "=")+1])
				if strings.EqualFold(strings.TrimSpace(val), "daily") {
					updatesDaily = true
				}
			}
		}
		if updatesDaily {
			results = append(results, store.AuditResult{
				Category: "cpanel", Name: "cp_updates", Title: "cPanel Auto-Updates",
				Status: "pass", Message: "UPDATES=daily in cpupdate.conf",
			})
		} else {
			results = append(results, store.AuditResult{
				Category: "cpanel", Name: "cp_updates", Title: "cPanel Auto-Updates",
				Status: "warn", Message: "cPanel auto-updates not set to daily",
				Fix: "Set UPDATES=daily in /etc/cpupdate.conf or WHM > Update Preferences.",
			})
		}
	}

	// CloudLinux-specific checks
	if serverType == "cloudlinux" {
		results = append(results, auditCloudLinux()...)
	}

	return results
}

func parseCpanelConfig(path string) map[string]string {
	conf := make(map[string]string)
	data, err := osFS.ReadFile(path)
	if err != nil {
		return conf
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "="); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			conf[key] = val
		}
	}
	return conf
}

func auditCloudLinux() []store.AuditResult {
	var results []store.AuditResult

	// cl_cagefs
	out, err := auditRunCmd("cagefsctl", "--cagefs-status")
	switch {
	case err != nil:
		results = append(results, store.AuditResult{
			Category: "cpanel", Name: "cl_cagefs", Title: "CageFS Enabled",
			Status: "warn", Message: "Cannot check CageFS status",
		})
	case strings.Contains(string(out), "Enabled"):
		results = append(results, store.AuditResult{
			Category: "cpanel", Name: "cl_cagefs", Title: "CageFS Enabled",
			Status: "pass", Message: "CageFS is enabled",
		})
	default:
		results = append(results, store.AuditResult{
			Category: "cpanel", Name: "cl_cagefs", Title: "CageFS Enabled",
			Status: "fail", Message: "CageFS is not enabled",
			Fix: "Enable CageFS: cagefsctl --enable-all",
		})
	}

	// cl_symlink_protection
	if data, err := osFS.ReadFile("/proc/sys/fs/enforce_symlinksifowner"); err == nil {
		val := strings.TrimSpace(string(data))
		n, _ := strconv.Atoi(val)
		if n >= 1 {
			results = append(results, store.AuditResult{
				Category: "cpanel", Name: "cl_symlink_protection", Title: "CloudLinux Symlink Protection",
				Status: "pass", Message: fmt.Sprintf("enforce_symlinksifowner = %s", val),
			})
		} else {
			results = append(results, store.AuditResult{
				Category: "cpanel", Name: "cl_symlink_protection", Title: "CloudLinux Symlink Protection",
				Status: "fail", Message: fmt.Sprintf("enforce_symlinksifowner = %s (expected >= 1)", val),
				Fix: "sysctl -w fs.enforce_symlinksifowner=1",
			})
		}
	}

	// cl_proc_virtualization
	if data, err := osFS.ReadFile("/proc/sys/fs/proc_can_see_other_uid"); err == nil {
		val := strings.TrimSpace(string(data))
		if val == "0" {
			results = append(results, store.AuditResult{
				Category: "cpanel", Name: "cl_proc_virtualization", Title: "CloudLinux /proc Virtualization",
				Status: "pass", Message: "proc_can_see_other_uid = 0",
			})
		} else {
			results = append(results, store.AuditResult{
				Category: "cpanel", Name: "cl_proc_virtualization", Title: "CloudLinux /proc Virtualization",
				Status: "fail", Message: fmt.Sprintf("proc_can_see_other_uid = %s (expected 0)", val),
				Fix: "sysctl -w fs.proc_can_see_other_uid=0",
			})
		}
	}

	return results
}

// --- PHP checks ---

func auditPHP(serverType string) []store.AuditResult {
	var results []store.AuditResult

	type phpInstall struct {
		version string // e.g. "8.1"
		shortID string // e.g. "81"
		iniPath string
		fpmDir  string // for FPM pool override merging
	}

	var installs []phpInstall

	// cPanel EA4 PHP installs
	eaInis, _ := osFS.Glob("/opt/cpanel/ea-php*/root/etc/php.ini")
	for _, ini := range eaInis {
		// Extract version from path: /opt/cpanel/ea-php81/root/etc/php.ini -> "81"
		dir := filepath.Dir(filepath.Dir(filepath.Dir(ini))) // /opt/cpanel/ea-php81/root -> /opt/cpanel/ea-php81
		base := filepath.Base(dir)                           // ea-php81
		shortID := strings.TrimPrefix(base, "ea-php")
		if len(shortID) >= 2 {
			ver := shortID[:len(shortID)-1] + "." + shortID[len(shortID)-1:]
			fpmDir := filepath.Join(dir, "root", "etc", "php-fpm.d")
			installs = append(installs, phpInstall{
				version: ver,
				shortID: shortID,
				iniPath: ini,
				fpmDir:  fpmDir,
			})
		}
	}

	// CloudLinux alt-php installs (skip Imunify360's internal PHP builds)
	if serverType == "cloudlinux" {
		altInis, _ := osFS.Glob("/opt/alt/php*/etc/php.ini")
		for _, ini := range altInis {
			dir := filepath.Dir(filepath.Dir(ini)) // /opt/alt/php81
			base := filepath.Base(dir)             // php81
			if strings.Contains(base, "-") {
				continue // skip php74-imunify, php81-hardened, etc.
			}
			shortID := strings.TrimPrefix(base, "php")
			if len(shortID) >= 2 {
				ver := shortID[:len(shortID)-1] + "." + shortID[len(shortID)-1:]
				installs = append(installs, phpInstall{
					version: ver,
					shortID: shortID,
					iniPath: ini,
				})
			}
		}
	}

	// Bare server fallback
	if len(installs) == 0 {
		out, err := auditRunCmd("php", "-i")
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(line, "Loaded Configuration File") {
					parts := strings.SplitN(line, "=>", 2)
					if len(parts) == 2 {
						iniPath := strings.TrimSpace(parts[1])
						if iniPath != "(none)" && iniPath != "" {
							installs = append(installs, phpInstall{
								version: "unknown",
								shortID: "system",
								iniPath: iniPath,
							})
						}
					}
				}
			}
		}
		// Try to get version for bare
		if len(installs) > 0 && installs[0].version == "unknown" {
			vout, verr := auditRunCmd("php", "-v")
			if verr == nil {
				first := strings.SplitN(string(vout), "\n", 2)[0]
				// "PHP 8.2.15 (cli) ..."
				fields := strings.Fields(first)
				if len(fields) >= 2 {
					verParts := strings.SplitN(fields[1], ".", 3)
					if len(verParts) >= 2 {
						installs[0].version = verParts[0] + "." + verParts[1]
						installs[0].shortID = verParts[0] + verParts[1]
					}
				}
			}
		}
	}

	for _, inst := range installs {
		data, err := osFS.ReadFile(inst.iniPath)
		if err != nil {
			continue
		}
		ini := parsePHPIni(string(data))

		// Merge FPM pool overrides if available
		if inst.fpmDir != "" {
			poolConfs, _ := osFS.Glob(filepath.Join(inst.fpmDir, "*.conf"))
			for _, pc := range poolConfs {
				pdata, perr := osFS.ReadFile(pc)
				if perr != nil {
					continue
				}
				for _, line := range strings.Split(string(pdata), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, ";") {
						continue
					}
					// php_admin_value[key] = val or php_value[key] = val
					for _, prefix := range []string{"php_admin_value[", "php_value["} {
						if strings.HasPrefix(line, prefix) {
							rest := strings.TrimPrefix(line, prefix)
							if idx := strings.Index(rest, "]"); idx > 0 {
								key := rest[:idx]
								valPart := rest[idx+1:]
								if eqIdx := strings.Index(valPart, "="); eqIdx >= 0 {
									val := strings.TrimSpace(valPart[eqIdx+1:])
									ini[key] = val
								}
							}
						}
					}
				}
			}
		}

		suffix := inst.shortID

		// php_version check
		major, minor := parsePHPVersion(inst.version)
		if major > 0 {
			if major < 8 || (major == 8 && minor < 1) {
				results = append(results, store.AuditResult{
					Category: "php", Name: "php_version_" + suffix, Title: fmt.Sprintf("PHP %s Version", inst.version),
					Status: "fail", Message: fmt.Sprintf("PHP %s is end-of-life", inst.version),
					Fix: fmt.Sprintf("Upgrade PHP %s to 8.1 or later. EOL versions receive no security patches.", inst.version),
				})
			} else {
				results = append(results, store.AuditResult{
					Category: "php", Name: "php_version_" + suffix, Title: fmt.Sprintf("PHP %s Version", inst.version),
					Status: "pass", Message: fmt.Sprintf("PHP %s is supported", inst.version),
				})
			}
		}

		// php_disable_functions
		df := strings.TrimSpace(ini["disable_functions"])
		if df == "" || strings.EqualFold(df, "none") {
			results = append(results, store.AuditResult{
				Category: "php", Name: "php_disable_functions_" + suffix, Title: fmt.Sprintf("PHP %s disable_functions", inst.version),
				Status: "fail", Message: "disable_functions is empty",
				Fix: fmt.Sprintf("Set disable_functions in %s to include dangerous functions like exec, system, passthru, shell_exec, popen, proc_open.", inst.iniPath),
			})
		} else {
			results = append(results, store.AuditResult{
				Category: "php", Name: "php_disable_functions_" + suffix, Title: fmt.Sprintf("PHP %s disable_functions", inst.version),
				Status: "pass", Message: "disable_functions is configured",
			})
		}

		// php_expose
		expose := strings.TrimSpace(strings.ToLower(ini["expose_php"]))
		if expose == "off" || expose == "0" {
			results = append(results, store.AuditResult{
				Category: "php", Name: "php_expose_" + suffix, Title: fmt.Sprintf("PHP %s expose_php", inst.version),
				Status: "pass", Message: "expose_php is off",
			})
		} else {
			results = append(results, store.AuditResult{
				Category: "php", Name: "php_expose_" + suffix, Title: fmt.Sprintf("PHP %s expose_php", inst.version),
				Status: "warn", Message: "expose_php is on — PHP version disclosed in headers",
				Fix: fmt.Sprintf("Set expose_php = Off in %s", inst.iniPath),
			})
		}

		// php_allow_url_fopen
		auf := strings.TrimSpace(strings.ToLower(ini["allow_url_fopen"]))
		if auf == "off" || auf == "0" {
			results = append(results, store.AuditResult{
				Category: "php", Name: "php_allow_url_fopen_" + suffix, Title: fmt.Sprintf("PHP %s allow_url_fopen", inst.version),
				Status: "pass", Message: "allow_url_fopen is off",
			})
		} else {
			results = append(results, store.AuditResult{
				Category: "php", Name: "php_allow_url_fopen_" + suffix, Title: fmt.Sprintf("PHP %s allow_url_fopen", inst.version),
				Status: "warn", Message: "allow_url_fopen is on — remote file inclusion risk",
				Fix: fmt.Sprintf("Set allow_url_fopen = Off in %s", inst.iniPath),
			})
		}

		// php_enable_dl
		edl := strings.TrimSpace(strings.ToLower(ini["enable_dl"]))
		if edl == "on" || edl == "1" {
			results = append(results, store.AuditResult{
				Category: "php", Name: "php_enable_dl_" + suffix, Title: fmt.Sprintf("PHP %s enable_dl", inst.version),
				Status: "fail", Message: "enable_dl is on — allows loading arbitrary shared objects",
				Fix: fmt.Sprintf("Set enable_dl = Off in %s", inst.iniPath),
			})
		} else {
			results = append(results, store.AuditResult{
				Category: "php", Name: "php_enable_dl_" + suffix, Title: fmt.Sprintf("PHP %s enable_dl", inst.version),
				Status: "pass", Message: "enable_dl is off",
			})
		}
	}

	return results
}

func parsePHPIni(content string) map[string]string {
	ini := make(map[string]string)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
			continue
		}
		if idx := strings.Index(line, "="); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			ini[key] = val
		}
	}
	return ini
}

func parsePHPVersion(ver string) (int, int) {
	parts := strings.SplitN(ver, ".", 3)
	if len(parts) < 2 {
		return 0, 0
	}
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	return major, minor
}

// --- Web server checks ---

func auditWebServer(serverType string) []store.AuditResult {
	var results []store.AuditResult

	// Find main config file
	var configPath string
	configPaths := []string{
		"/etc/apache2/conf/httpd.conf",          // cPanel EA4
		"/usr/local/lsws/conf/httpd_config.xml", // LiteSpeed
		"/etc/httpd/conf/httpd.conf",            // RHEL/CentOS bare
		"/etc/apache2/apache2.conf",             // Debian/Ubuntu bare
	}
	for _, p := range configPaths {
		if _, err := osFS.Stat(p); err == nil {
			configPath = p
			break
		}
	}

	if configPath != "" {
		configData, err := osFS.ReadFile(configPath)
		if err == nil {
			configContent := string(configData)

			// Table-driven directive checks
			type directiveCheck struct {
				id, title, directive string
				goodValues           []string
			}
			dirChecks := []directiveCheck{
				{"web_server_tokens", "ServerTokens", "ServerTokens", []string{"prod", "productonly"}},
				{"web_server_signature", "ServerSignature", "ServerSignature", []string{"off"}},
				{"web_trace_enable", "TraceEnable", "TraceEnable", []string{"off"}},
				{"web_file_etag", "FileETag", "FileETag", []string{"none"}},
			}

			for _, dc := range dirChecks {
				found := false
				var foundVal string
				for _, line := range strings.Split(configContent, "\n") {
					trimmed := strings.TrimSpace(line)
					if strings.HasPrefix(trimmed, "#") {
						continue
					}
					if strings.HasPrefix(strings.ToLower(trimmed), strings.ToLower(dc.directive)+" ") {
						parts := strings.Fields(trimmed)
						if len(parts) >= 2 {
							foundVal = parts[1]
							found = true
						}
					}
				}

				if !found {
					results = append(results, store.AuditResult{
						Category: "webserver", Name: dc.id, Title: dc.title,
						Status: "warn", Message: fmt.Sprintf("%s not set in %s", dc.directive, configPath),
						Fix: fmt.Sprintf("Add '%s %s' to %s", dc.directive, dc.goodValues[0], configPath),
					})
					continue
				}

				isGood := false
				for _, gv := range dc.goodValues {
					if strings.EqualFold(foundVal, gv) {
						isGood = true
						break
					}
				}
				if isGood {
					results = append(results, store.AuditResult{
						Category: "webserver", Name: dc.id, Title: dc.title,
						Status: "pass", Message: fmt.Sprintf("%s = %s", dc.directive, foundVal),
					})
				} else {
					results = append(results, store.AuditResult{
						Category: "webserver", Name: dc.id, Title: dc.title,
						Status: "fail", Message: fmt.Sprintf("%s = %s", dc.directive, foundVal),
						Fix: fmt.Sprintf("Set '%s %s' in %s", dc.directive, dc.goodValues[0], configPath),
					})
				}
			}

			// Directory listing check
			hasIndexes := false
			for _, line := range strings.Split(configContent, "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "#") {
					continue
				}
				lower := strings.ToLower(trimmed)
				if strings.Contains(lower, "options") && strings.Contains(lower, "indexes") && !strings.Contains(lower, "-indexes") {
					hasIndexes = true
					break
				}
			}
			if hasIndexes {
				results = append(results, store.AuditResult{
					Category: "webserver", Name: "web_directory_listing", Title: "Directory Listing",
					Status: "warn", Message: "Global config enables directory listing (Options Indexes)",
					Fix: "Replace 'Indexes' with '-Indexes' in Options directives.",
				})
			} else {
				results = append(results, store.AuditResult{
					Category: "webserver", Name: "web_directory_listing", Title: "Directory Listing",
					Status: "pass", Message: "No global directory listing enabled",
				})
			}
		}
	}

	// TLS version checks: probe with openssl
	for _, tc := range []struct {
		id, title, flag, version string
	}{
		{"web_tls_version", "Legacy TLS Disabled", "-tls1", "TLSv1.0"},
		{"web_tls11_version", "TLS 1.1 Disabled", "-tls1_1", "TLSv1.1"},
	} {
		out, err := auditRunCmd("openssl", "s_client", "-connect", "localhost:443", tc.flag)
		output := string(out)
		// If the handshake succeeds, output contains "SSL-Session:" without ":error:" on the same handshake
		succeeded := err == nil && strings.Contains(output, "SSL-Session:") && !strings.Contains(output, ":error:")
		if succeeded {
			results = append(results, store.AuditResult{
				Category: "webserver", Name: tc.id, Title: tc.title,
				Status: "fail", Message: fmt.Sprintf("Server accepts %s connections", tc.version),
				Fix: fmt.Sprintf("Disable %s in your web server's SSL configuration. Minimum should be TLSv1.2.", tc.version),
			})
		} else {
			results = append(results, store.AuditResult{
				Category: "webserver", Name: tc.id, Title: tc.title,
				Status: "pass", Message: fmt.Sprintf("%s is rejected", tc.version),
			})
		}
	}

	return results
}

// --- Mail checks ---

func auditMail() []store.AuditResult {
	var results []store.AuditResult

	// mail_root_forwarder
	if info, err := osFS.Stat("/root/.forward"); err != nil {
		results = append(results, store.AuditResult{
			Category: "mail", Name: "mail_root_forwarder", Title: "Root Mail Forwarder",
			Status: "warn", Message: "/root/.forward does not exist — root mail may go unread",
			Fix: "Create /root/.forward with an email address to receive root's mail.",
		})
	} else if info.Size() == 0 {
		results = append(results, store.AuditResult{
			Category: "mail", Name: "mail_root_forwarder", Title: "Root Mail Forwarder",
			Status: "warn", Message: "/root/.forward is empty — root mail may go unread",
			Fix: "Add an email address to /root/.forward to receive root's mail.",
		})
	} else {
		results = append(results, store.AuditResult{
			Category: "mail", Name: "mail_root_forwarder", Title: "Root Mail Forwarder",
			Status: "pass", Message: "Root mail forwarding is configured",
		})
	}

	// Get exim config for multiple checks
	eximOut, eximErr := auditRunCmd("exim", "-bP")
	eximConfig := ""
	if eximErr == nil {
		eximConfig = string(eximOut)
	}

	// mail_exim_logging
	if eximConfig != "" {
		lower := strings.ToLower(eximConfig)
		if strings.Contains(lower, "+arguments") || strings.Contains(lower, "+all") {
			results = append(results, store.AuditResult{
				Category: "mail", Name: "mail_exim_logging", Title: "Exim Argument Logging",
				Status: "pass", Message: "Exim logs include +arguments",
			})
		} else {
			results = append(results, store.AuditResult{
				Category: "mail", Name: "mail_exim_logging", Title: "Exim Argument Logging",
				Status: "warn", Message: "Exim log_selector does not include +arguments",
				Fix: "Add '+arguments' to log_selector in exim configuration for better forensics.",
			})
		}
	} else {
		results = append(results, store.AuditResult{
			Category: "mail", Name: "mail_exim_logging", Title: "Exim Argument Logging",
			Status: "warn", Message: "Cannot query exim configuration",
		})
	}

	// mail_exim_tls: check for SSLv2 in tls_require_ciphers
	// +no_sslv2 in openssl_options means SSLv2 is DISABLED (good).
	// Only flag if SSLv2 is referenced WITHOUT +no_ prefix.
	if eximConfig != "" {
		lower := strings.ToLower(eximConfig)
		hasSslv2 := strings.Contains(lower, "sslv2")
		isDisabled := strings.Contains(lower, "+no_sslv2") || strings.Contains(lower, "no_sslv2")
		if hasSslv2 && !isDisabled {
			results = append(results, store.AuditResult{
				Category: "mail", Name: "mail_exim_tls", Title: "Exim TLS Ciphers",
				Status: "fail", Message: "Exim allows SSLv2 connections",
				Fix: "Add '+no_sslv2' to openssl_options in exim configuration.",
			})
		} else {
			results = append(results, store.AuditResult{
				Category: "mail", Name: "mail_exim_tls", Title: "Exim TLS Ciphers",
				Status: "pass", Message: "SSLv2 is disabled in exim TLS configuration",
			})
		}
	}

	// mail_secure_auth: check /etc/exim.conf.localopts
	if data, err := osFS.ReadFile("/etc/exim.conf.localopts"); err == nil {
		content := string(data)
		if strings.Contains(content, "require_secure_auth=0") {
			results = append(results, store.AuditResult{
				Category: "mail", Name: "mail_secure_auth", Title: "Exim Secure Authentication",
				Status: "fail", Message: "require_secure_auth is disabled in /etc/exim.conf.localopts",
				Fix: "Remove or set require_secure_auth=1 in /etc/exim.conf.localopts.",
			})
		} else {
			results = append(results, store.AuditResult{
				Category: "mail", Name: "mail_secure_auth", Title: "Exim Secure Authentication",
				Status: "pass", Message: "Secure authentication is not disabled",
			})
		}
	} else {
		results = append(results, store.AuditResult{
			Category: "mail", Name: "mail_secure_auth", Title: "Exim Secure Authentication",
			Status: "pass", Message: "No local exim overrides file found (default is secure)",
		})
	}

	// mail_dovecot_tls: check ssl_min_protocol
	// Use 'doveconf -a' for the effective config — cPanel manages Dovecot
	// settings outside the standard config files, so file parsing misses
	// them. Routed through cmdExec so tests can mock the doveconf output.
	dovecotTLS := false
	if out, err := cmdExec.Run("doveconf", "-a"); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "ssl_min_protocol") {
				val := strings.TrimSpace(strings.TrimPrefix(trimmed, "ssl_min_protocol"))
				val = strings.TrimLeft(val, "= ")
				if strings.Contains(val, "TLSv1.2") || strings.Contains(val, "TLSv1.3") {
					dovecotTLS = true
				}
			}
		}
	} else {
		// Fallback: try config files
		for _, path := range []string{"/etc/dovecot/conf.d/10-ssl.conf", "/etc/dovecot/dovecot.conf"} {
			data, readErr := osFS.ReadFile(path)
			if readErr != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "#") {
					continue
				}
				if strings.HasPrefix(trimmed, "ssl_min_protocol") {
					val := strings.TrimSpace(strings.TrimPrefix(trimmed, "ssl_min_protocol"))
					val = strings.TrimLeft(val, "= ")
					if strings.Contains(val, "TLSv1.2") || strings.Contains(val, "TLSv1.3") {
						dovecotTLS = true
					}
				}
			}
		}
	}
	if dovecotTLS {
		results = append(results, store.AuditResult{
			Category: "mail", Name: "mail_dovecot_tls", Title: "Dovecot TLS Minimum",
			Status: "pass", Message: "Dovecot ssl_min_protocol is TLSv1.2 or higher",
		})
	} else {
		if _, err := osFS.Stat("/etc/dovecot/dovecot.conf"); err != nil {
			results = append(results, store.AuditResult{
				Category: "mail", Name: "mail_dovecot_tls", Title: "Dovecot TLS Minimum",
				Status: "warn", Message: "Dovecot configuration not found",
			})
		} else {
			results = append(results, store.AuditResult{
				Category: "mail", Name: "mail_dovecot_tls", Title: "Dovecot TLS Minimum",
				Status: "fail", Message: "Dovecot ssl_min_protocol not set to TLSv1.2 or higher",
				Fix: "Set 'ssl_min_protocol = TLSv1.2' in /etc/dovecot/conf.d/10-ssl.conf.",
			})
		}
	}

	return results
}
