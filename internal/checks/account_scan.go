package checks

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/state"
)

// ScanAccount restricts filesystem-based checks to a single account.
// Protected by scanMu - concurrent scans are serialized to prevent scope bleed.
var (
	ScanAccount string
	scanMu      sync.Mutex
)

// RunAccountScan runs all applicable checks scoped to a single cPanel account.
// Returns findings for that account only. Does NOT trigger auto-response actions.
func RunAccountScan(cfg *config.Config, store *state.Store, account string) []alert.Finding {
	// Verify account exists
	homeDir := filepath.Join("/home", account)
	if _, err := osFS.Stat(homeDir); os.IsNotExist(err) {
		return []alert.Finding{{
			Severity:  alert.Warning,
			Check:     "account_scan",
			Message:   fmt.Sprintf("Account '%s' not found (no /home/%s directory)", account, account),
			Timestamp: time.Now(),
		}}
	}

	// Acquire scan lock - only one account scan at a time to prevent scope bleed
	scanMu.Lock()
	ScanAccount = account
	defer func() {
		ScanAccount = ""
		scanMu.Unlock()
	}()

	// Account-scoped checks (filesystem + account-specific)
	accountChecks := []namedCheck{
		{"webshells", CheckWebshells},
		{"htaccess", CheckHtaccess},
		{"wp_core", CheckWPCore},
		{"php_content", CheckPHPContent},
		{"phishing", CheckPhishing},
		{"filesystem", CheckFilesystem},
		{"group_writable_php", CheckGroupWritablePHP},
		{"nulled_plugins", CheckNulledPlugins},
		{"open_basedir", CheckOpenBasedir},
		{"symlink_attacks", CheckSymlinkAttacks},
		{"db_content", CheckDatabaseContent},
		{"php_config_changes", CheckPHPConfigChanges},
	}

	// Account-specific checks that need the account name
	accountChecks = append(accountChecks,
		namedCheck{"ssh_keys_account", makeAccountSSHKeyCheck(account)},
		namedCheck{"crontab_account", makeAccountCrontabCheck(account)},
		namedCheck{"backdoor_binaries", makeAccountBackdoorCheck(account)},
	)

	// Run with bounded parallelism - filesystem checks all walk the same
	// directory tree, so too many concurrent checks starve each other on
	// loaded servers with slow I/O.
	var mu sync.Mutex
	var findings []alert.Finding
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4) // max 4 concurrent checks

	for _, nc := range accountChecks {
		wg.Add(1)
		go func(c namedCheck) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
			done := make(chan []alert.Finding, 1)
			go func() {
				done <- c.fn(ctx, cfg, store)
			}()

			select {
			case results := <-done:
				cancel()
				if len(results) > 0 {
					mu.Lock()
					findings = append(findings, results...)
					mu.Unlock()
				}
			case <-ctx.Done():
				cancel()
				mu.Lock()
				findings = append(findings, alert.Finding{
					Severity:  alert.Warning,
					Check:     "check_timeout",
					Message:   fmt.Sprintf("Account scan check '%s' timed out", c.name),
					Timestamp: time.Now(),
				})
				mu.Unlock()
			}
		}(nc)
	}

	wg.Wait()

	now := time.Now()
	for i := range findings {
		if findings[i].Timestamp.IsZero() {
			findings[i].Timestamp = now
		}
	}

	// Filter findings to only include this account's paths
	var filtered []alert.Finding
	accountPrefix := "/home/" + account + "/"
	for _, f := range findings {
		// Include if the finding mentions this account's path, or has no path at all
		if strings.Contains(f.Message, accountPrefix) ||
			strings.Contains(f.Details, accountPrefix) ||
			(!strings.Contains(f.Message, "/home/") && !strings.Contains(f.Details, "/home/")) {
			filtered = append(filtered, f)
		}
	}

	return filtered
}

// GetScanHomeDirs returns the list of home directories to scan.
// If ScanAccount is set, returns only that account. Otherwise returns all.
func GetScanHomeDirs() ([]os.DirEntry, error) {
	scanMu.Lock()
	account := ScanAccount
	scanMu.Unlock()
	if account != "" {
		// Return a single synthetic DirEntry for the target account
		info, err := osFS.Stat(filepath.Join("/home", account))
		if err != nil {
			return nil, err
		}
		return []os.DirEntry{fakeDirEntry{info}}, nil
	}
	return osFS.ReadDir("/home")
}

// ResolveWebRoots returns the list of directory paths CSM should scan for
// web-facing content (wp-config.php, .htaccess, public_html trees, etc.).
//
// Resolution order:
//  1. If cfg.AccountRoots is set, expand each glob and return the result.
//     Explicit config always wins.
//  2. On cPanel hosts (detected via platform.Detect), fall back to
//     /home/*/public_html for backward compatibility.
//  3. On non-cPanel hosts with no config, return an empty list. Callers
//     should treat this as "no scanning" and skip cleanly.
//
// Each returned path is an absolute directory that exists on disk.
func ResolveWebRoots(cfg *config.Config) []string {
	var patterns []string
	switch {
	case len(cfg.AccountRoots) > 0:
		patterns = cfg.AccountRoots
	case platform.Detect().IsCPanel():
		patterns = []string{"/home/*/public_html"}
	default:
		return nil
	}

	var roots []string
	seen := make(map[string]struct{})
	for _, pattern := range patterns {
		matches, err := osFS.Glob(pattern)
		if err != nil || len(matches) == 0 {
			continue
		}
		for _, m := range matches {
			info, err := osFS.Stat(m)
			if err != nil || !info.IsDir() {
				continue
			}
			if _, ok := seen[m]; ok {
				continue
			}
			seen[m] = struct{}{}
			roots = append(roots, m)
		}
	}
	return roots
}

// fakeDirEntry wraps os.FileInfo to implement os.DirEntry.
type fakeDirEntry struct {
	fi os.FileInfo
}

func (f fakeDirEntry) Name() string               { return f.fi.Name() }
func (f fakeDirEntry) IsDir() bool                { return f.fi.IsDir() }
func (f fakeDirEntry) Type() os.FileMode          { return f.fi.Mode().Type() }
func (f fakeDirEntry) Info() (os.FileInfo, error) { return f.fi, nil }

// makeAccountSSHKeyCheck creates a check for SSH keys of a specific account.
func makeAccountSSHKeyCheck(account string) CheckFunc {
	return func(_ context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
		var findings []alert.Finding
		keyFile := filepath.Join("/home", account, ".ssh", "authorized_keys")
		hash, err := hashFileContent(keyFile)
		if err != nil {
			return nil
		}
		key := fmt.Sprintf("_ssh_user_keys:%s", keyFile)
		prev, exists := store.GetRaw(key)
		if exists && prev != hash {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "ssh_keys",
				Message:  fmt.Sprintf("User authorized_keys modified: %s", keyFile),
			})
		}
		return findings
	}
}

// makeAccountCrontabCheck creates a check for a specific account's crontab.
func makeAccountCrontabCheck(account string) CheckFunc {
	return func(_ context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
		var findings []alert.Finding
		crontabFile := filepath.Join("/var/spool/cron", account)
		data, err := osFS.ReadFile(crontabFile)
		if err != nil {
			return nil
		}

		suspiciousPatterns := []string{
			"defunct-kernel", "base64_decode", "eval(",
			"/dev/tcp/", "gsocket", "gs-netcat",
			"reverse", "bash -i", "nc -e", "ncat -e",
			"python -c", "perl -e", "SEED PRNG",
		}

		content := string(data)
		for _, pattern := range suspiciousPatterns {
			if strings.Contains(strings.ToLower(content), strings.ToLower(pattern)) {
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "suspicious_crontab",
					Message:  fmt.Sprintf("Suspicious pattern in crontab for %s: %s", account, pattern),
					Details:  fmt.Sprintf("File: /var/spool/cron/%s\nContent:\n%s", account, content),
				})
			}
		}
		return findings
	}
}

// makeAccountBackdoorCheck creates a check for backdoor binaries in account's .config.
func makeAccountBackdoorCheck(account string) CheckFunc {
	return func(_ context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
		var findings []alert.Finding

		backdoorNames := map[string]bool{
			"defunct": true, "defunct.dat": true, "gs-netcat": true,
			"gs-sftp": true, "gs-mount": true, "gsocket": true,
		}

		patterns := []string{
			filepath.Join("/home", account, ".config", "htop", "*"),
			filepath.Join("/home", account, ".config", "*", "*"),
		}

		for _, pattern := range patterns {
			matches, _ := osFS.Glob(pattern)
			for _, path := range matches {
				if backdoorNames[filepath.Base(path)] {
					info, _ := osFS.Stat(path)
					var details string
					if info != nil {
						details = fmt.Sprintf("Size: %d bytes, Mtime: %s", info.Size(), info.ModTime().Format("2006-01-02 15:04:05"))
					}
					findings = append(findings, alert.Finding{
						Severity: alert.Critical,
						Check:    "backdoor_binary",
						Message:  fmt.Sprintf("Backdoor binary found: %s", path),
						Details:  details,
					})
				}
			}
		}
		return findings
	}
}

// LookupUID returns the UID for a system account name, or -1 if not found.
func LookupUID(account string) int {
	u, err := user.Lookup(account)
	if err != nil {
		return -1
	}
	uid := 0
	fmt.Sscanf(u.Uid, "%d", &uid)
	return uid
}
