package checks

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// CheckKernelModules compares loaded kernel modules against baseline.
// All modules present at baseline time are considered known.
// Only modules loaded AFTER baseline trigger alerts.
func CheckKernelModules(_ *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	modules := loadModuleList()
	if len(modules) == 0 {
		return nil
	}

	// Check if baseline exists for kernel modules
	_, baselineExists := store.GetRaw("_kmod_baseline_set")

	if !baselineExists {
		// First run - store all current modules as baseline
		for _, mod := range modules {
			store.SetRaw("_kmod:"+mod, "baseline")
		}
		store.SetRaw("_kmod_baseline_set", "true")
		return nil
	}

	// Check for modules not seen at baseline
	for _, mod := range modules {
		key := "_kmod:" + mod
		_, known := store.GetRaw(key)
		if !known {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "kernel_module",
				Message:  fmt.Sprintf("New kernel module loaded after baseline: %s", mod),
				Details:  "This module was not present when CSM baseline was set. Verify it is legitimate.",
			})
			// Store it so we don't re-alert
			store.SetRaw(key, "new")
		}
	}

	return findings
}

func loadModuleList() []string {
	f, err := os.Open("/proc/modules")
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var modules []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 1 {
			modules = append(modules, fields[0])
		}
	}
	return modules
}

// CheckRPMIntegrity verifies critical system binaries haven't been modified.
// Only checks a small set of security-critical packages.
func CheckRPMIntegrity(_ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	criticalPackages := []string{
		"openssh-server",
		"shadow-utils",
		"sudo",
		"coreutils",
		"util-linux",
		"passwd",
	}

	for _, pkg := range criticalPackages {
		out, err := runCmd("rpm", "-V", pkg)
		if err != nil || out == nil {
			continue
		}

		output := strings.TrimSpace(string(out))
		if output == "" {
			continue
		}

		// Parse rpm -V output: each line starts with flags
		// S=size, 5=md5, T=mtime, etc. We care about S, 5, and M (mode)
		for _, line := range strings.Split(output, "\n") {
			if len(line) < 9 {
				continue
			}
			flags := line[:9]
			file := strings.TrimSpace(line[9:])

			// Skip config files (c) and documentation (d)
			if strings.Contains(line, " c ") || strings.Contains(line, " d ") {
				continue
			}

			// Check for size (S) or checksum (5) changes on binaries
			if strings.Contains(flags, "S") || strings.Contains(flags, "5") {
				// Only flag binary files, not configs
				if strings.HasPrefix(file, "/usr/bin/") || strings.HasPrefix(file, "/usr/sbin/") ||
					strings.HasPrefix(file, "/bin/") || strings.HasPrefix(file, "/sbin/") {
					findings = append(findings, alert.Finding{
						Severity: alert.Critical,
						Check:    "rpm_integrity",
						Message:  fmt.Sprintf("Modified system binary: %s (package: %s)", file, pkg),
						Details:  fmt.Sprintf("RPM verification flags: %s", flags),
					})
				}
			}
		}
	}

	return findings
}

// CheckMySQLUsers queries for MySQL users with elevated privileges
// that aren't standard cPanel-managed users.
func CheckMySQLUsers(_ *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	out, err := runCmd("mysql", "-N", "-B", "-e",
		"SELECT user, host FROM mysql.user WHERE Super_priv='Y' AND user NOT IN ('root','mysql.session','mysql.sys','mysql.infoschema','debian-sys-maint')")
	if err != nil || out == nil {
		return nil
	}

	output := strings.TrimSpace(string(out))
	if output == "" {
		return nil
	}

	// Track known MySQL superusers
	hash := hashBytes(out)
	key := "_mysql_super_users"
	prev, exists := store.GetRaw(key)
	if exists && prev != hash {
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "mysql_superuser",
			Message:  "MySQL superuser accounts changed",
			Details:  fmt.Sprintf("Current superusers:\n%s", output),
		})
	}
	store.SetRaw(key, hash)

	return findings
}

// CheckGroupWritablePHP scans for PHP files that are group-writable
// where the group is the web server (nobody/www-data). This allows
// webshells to persist by the web server modifying PHP files.
func CheckGroupWritablePHP(_ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	// Get web server group GIDs
	webGroupGIDs := getWebServerGIDs()
	if len(webGroupGIDs) == 0 {
		return nil
	}

	homeDirs, _ := os.ReadDir("/home")
	for _, homeEntry := range homeDirs {
		if !homeEntry.IsDir() {
			continue
		}
		docRoot := fmt.Sprintf("/home/%s/public_html", homeEntry.Name())
		scanGroupWritablePHP(docRoot, 4, webGroupGIDs, &findings)
	}

	return findings
}

func scanGroupWritablePHP(dir string, maxDepth int, webGIDs map[uint32]bool, findings *[]alert.Finding) {
	if maxDepth <= 0 {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		name := entry.Name()
		fullPath := dir + "/" + name

		if entry.IsDir() {
			// Skip known large/safe dirs
			if name == "cache" || name == "node_modules" || name == "vendor" {
				continue
			}
			scanGroupWritablePHP(fullPath, maxDepth-1, webGIDs, findings)
			continue
		}

		if !strings.HasSuffix(strings.ToLower(name), ".php") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Check group-write bit
		if info.Mode()&0020 == 0 {
			continue
		}

		// Check if group is web server
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		if webGIDs[stat.Gid] {
			*findings = append(*findings, alert.Finding{
				Severity: alert.High,
				Check:    "group_writable_php",
				Message:  fmt.Sprintf("Web-server group-writable PHP: %s", fullPath),
				Details:  fmt.Sprintf("Mode: %s, GID: %d", info.Mode(), stat.Gid),
			})
		}
	}
}

func getWebServerGIDs() map[uint32]bool {
	gids := make(map[uint32]bool)
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return gids
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		name := fields[0]
		if name == "nobody" || name == "www-data" || name == "apache" || name == "www" {
			gid := uint32(0)
			fmt.Sscanf(fields[2], "%d", &gid)
			gids[gid] = true
		}
	}
	return gids
}
