package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// CheckOpenBasedir verifies that each cPanel account has proper PHP
// isolation via CageFS and/or open_basedir.
// Flags accounts where CageFS is disabled AND open_basedir is not set.
func CheckOpenBasedir(_ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	// Check global CageFS mode
	cageFSMode := getCageFSMode()

	// Get list of disabled CageFS users (if mode is "Enable All", check exceptions)
	disabledUsers := getCageFSDisabledUsers(cageFSMode)

	// For users without CageFS, check if open_basedir is set
	userDirs, _ := os.ReadDir("/var/cpanel/users")
	for _, userEntry := range userDirs {
		user := userEntry.Name()

		// Skip if CageFS is active for this user
		if !disabledUsers[user] {
			continue
		}

		// CageFS is disabled for this user - check open_basedir
		if !hasOpenBasedir(user) {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "open_basedir",
				Message:  fmt.Sprintf("Account %s has no PHP isolation: CageFS disabled and no open_basedir", user),
				Details:  "This account's PHP scripts can read any file on the server including other accounts' wp-config.php and /etc/shadow",
			})
		}
	}

	return findings
}

func getCageFSMode() string {
	// CageFS mode file
	data, err := os.ReadFile("/etc/cagefs/cagefs.mp")
	if err != nil {
		return "unknown"
	}
	content := strings.TrimSpace(string(data))
	if content != "" {
		return "enabled"
	}
	return "unknown"
}

func getCageFSDisabledUsers(mode string) map[string]bool {
	disabled := make(map[string]bool)

	// Check cagefsctl --list-disabled
	out, _ := runCmd("cagefsctl", "--list-disabled")
	if out != nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			user := strings.TrimSpace(line)
			if user != "" {
				disabled[user] = true
			}
		}
	}

	// If mode is unknown (no CageFS), all users are "disabled"
	if mode == "unknown" && len(disabled) == 0 {
		userDirs, _ := os.ReadDir("/var/cpanel/users")
		for _, u := range userDirs {
			disabled[u.Name()] = true
		}
	}

	return disabled
}

func hasOpenBasedir(user string) bool {
	// Check .user.ini in public_html
	userIni := filepath.Join("/home", user, "public_html", ".user.ini")
	if data, err := os.ReadFile(userIni); err == nil {
		if strings.Contains(strings.ToLower(string(data)), "open_basedir") {
			return true
		}
	}

	// Check .htaccess for php_value open_basedir
	htaccess := filepath.Join("/home", user, "public_html", ".htaccess")
	if data, err := os.ReadFile(htaccess); err == nil {
		if strings.Contains(strings.ToLower(string(data)), "open_basedir") {
			return true
		}
	}

	// Check per-user PHP config set via cPanel MultiPHP
	phpConfDirs, _ := filepath.Glob("/opt/cpanel/ea-php*/root/etc/php.d/")
	for _, confDir := range phpConfDirs {
		userConf := filepath.Join(confDir, "local.ini")
		if data, err := os.ReadFile(userConf); err == nil {
			if strings.Contains(string(data), "open_basedir") {
				return true
			}
		}
	}

	return false
}

// CheckSymlinkAttacks detects symbolic links inside user public_html
// directories that point outside the account's own directory.
// This is a classic shared hosting attack to read other users' files.
func CheckSymlinkAttacks(_ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	homeDirs, _ := GetScanHomeDirs()
	for _, homeEntry := range homeDirs {
		if !homeEntry.IsDir() {
			continue
		}
		user := homeEntry.Name()
		homeDir := filepath.Join("/home", user)
		docRoot := filepath.Join(homeDir, "public_html")

		scanForMaliciousSymlinks(docRoot, user, homeDir, 4, &findings)
	}

	return findings
}

func scanForMaliciousSymlinks(dir, user, homeDir string, maxDepth int, findings *[]alert.Finding) {
	if maxDepth <= 0 {
		return
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		fullPath := filepath.Join(dir, entry.Name())

		// Check if it's a symlink
		if entry.Type()&os.ModeSymlink == 0 {
			if entry.IsDir() {
				scanForMaliciousSymlinks(fullPath, user, homeDir, maxDepth-1, findings)
			}
			continue
		}

		// It's a symlink - read the target
		target, err := os.Readlink(fullPath)
		if err != nil {
			continue
		}

		// Resolve relative targets
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(fullPath), target)
		}
		target = filepath.Clean(target)

		// Check if target is outside the user's home
		if isSymlinkSafe(target, user, homeDir) {
			continue
		}

		// Check if target points to another user's home
		if strings.HasPrefix(target, "/home/") {
			parts := strings.SplitN(target[6:], "/", 2)
			if len(parts) > 0 && parts[0] != user {
				*findings = append(*findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "symlink_attack",
					Message:  fmt.Sprintf("Symlink to another user's directory: %s -> %s", fullPath, target),
					Details:  fmt.Sprintf("User: %s, target user: %s\nThis could be used to read other accounts' files", user, parts[0]),
				})
				continue
			}
		}

		// Check if target points to sensitive system files
		sensitiveTargets := []string{"/etc/shadow", "/etc/passwd", "/root/"}
		for _, sens := range sensitiveTargets {
			if strings.HasPrefix(target, sens) {
				*findings = append(*findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "symlink_attack",
					Message:  fmt.Sprintf("Symlink to sensitive system file: %s -> %s", fullPath, target),
					Details:  fmt.Sprintf("User: %s", user),
				})
				break
			}
		}
	}
}

func isSymlinkSafe(target, user, homeDir string) bool {
	// Inside own home directory
	if strings.HasPrefix(target, homeDir+"/") || target == homeDir {
		return true
	}

	// Standard cPanel-created symlinks
	safeTargets := []string{
		"/etc/apache2/logs/",
		"/usr/local/apache/logs/",
		"/var/cpanel/",
		"/opt/cpanel/",
		"/usr/",
		"/var/lib/mysql/",
		"/var/run/",
	}
	for _, safe := range safeTargets {
		if strings.HasPrefix(target, safe) {
			return true
		}
	}

	return false
}
