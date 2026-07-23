package checks

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// CheckPHPConfigChanges monitors .user.ini and php.ini files anywhere under an
// account's document roots for settings that weaken PHP security (disable_functions
// cleared or neutralized, allow_url_include enabled, open_basedir removed). It runs
// as a deep check; the fanotify watcher also catches these writes in real-time.
func CheckPHPConfigChanges(ctx context.Context, _ *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	homeDirs, _ := GetScanHomeDirs(ctx)
	for _, homeEntry := range homeDirs {
		if !homeEntry.IsDir() {
			continue
		}
		user := homeEntry.Name()

		// Collect every .user.ini and php.ini under the account's document
		// roots. An attacker plants a php.ini (or a nested .user.ini) deep in
		// the tree -- e.g. wp-includes/assets/php.ini -- to weaken PHP, so the
		// scan cannot stop at the docroot root or watch .user.ini alone.
		roots := []string{filepath.Join("/home", user, "public_html")}
		subDirs, _ := osFS.ReadDir(filepath.Join("/home", user))
		for _, sd := range subDirs {
			if sd.IsDir() && sd.Name() != "public_html" && sd.Name() != "mail" &&
				!strings.HasPrefix(sd.Name(), ".") && sd.Name() != "etc" &&
				sd.Name() != "logs" && sd.Name() != "ssl" && sd.Name() != "tmp" {
				roots = append(roots, filepath.Join("/home", user, sd.Name()))
			}
		}

		var iniPaths []string
		for _, root := range roots {
			iniPaths = append(iniPaths, collectPHPIniFiles(root, phpIniWalkMaxDepth)...)
		}

		for _, iniPath := range iniPaths {
			// Read once, then hash and analyze the same bytes so a file that
			// changes between two reads cannot slip past change detection.
			data, err := osFS.ReadFile(iniPath)
			if err != nil {
				continue
			}
			sum := sha256.Sum256(data)
			hash := fmt.Sprintf("%x", sum[:])

			key := "_phpini:" + iniPath
			prev, exists := store.GetRaw(key)
			store.SetRaw(key, hash)

			if exists && prev == hash {
				continue // already assessed at this content
			}

			content := strings.ToLower(string(data))

			// A newly-seen file is judged on the strong, low-false-positive
			// bypass signals alone so a benign new .user.ini stays quiet; a
			// file whose content changed gets the full directive analysis.
			var dangerous []string
			if exists {
				dangerous = analyzePHPINI(content)
			} else {
				dangerous = phpINISecurityBypass(content)
			}
			if len(dangerous) > 0 {
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "php_config_change",
					Message:  fmt.Sprintf("Dangerous PHP configuration: %s (user: %s)", iniPath, user),
					Details:  fmt.Sprintf("Dangerous settings:\n- %s", strings.Join(dangerous, "\n- ")),
					FilePath: iniPath,
				})
			}
		}
	}

	return findings
}

func analyzePHPINI(content string) []string {
	var dangerous []string

	// disable_functions being cleared or reduced
	if strings.Contains(content, "disable_functions") {
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(line, "disable_functions") {
				// Check if it's being set to empty or very short
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					val := strings.TrimSpace(parts[1])
					if val == "" || val == "\"\"" || val == "''" || val == "none" {
						dangerous = append(dangerous, "disable_functions cleared (all PHP functions enabled)")
					}
				}
			}
		}
	}

	// Dangerous functions being enabled
	dangerousFuncs := []string{
		"exec", "system", "passthru", "shell_exec",
		"popen", "proc_open", "pcntl_exec",
	}
	if strings.Contains(content, "disable_functions") {
		// Check if dangerous functions are NOT in the disable list
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "disable_functions") {
				for _, fn := range dangerousFuncs {
					if !strings.Contains(line, fn) {
						// This dangerous function is not disabled
						dangerous = append(dangerous, fmt.Sprintf("%s not in disable_functions", fn))
					}
				}
				break
			}
		}
	}

	// allow_url_fopen / allow_url_include being enabled
	if strings.Contains(content, "allow_url_include") {
		for _, line := range strings.Split(content, "\n") {
			if strings.Contains(line, "allow_url_include") && (strings.Contains(line, "on") || strings.Contains(line, "1")) {
				dangerous = append(dangerous, "allow_url_include enabled (remote code inclusion)")
			}
		}
	}

	// open_basedir being removed
	if strings.Contains(content, "open_basedir") {
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "open_basedir") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					val := strings.TrimSpace(parts[1])
					if val == "" || val == "/" || val == "\"\"" {
						dangerous = append(dangerous, "open_basedir cleared or set to / (no restriction)")
					}
				}
			}
		}
	}

	return dangerous
}

// phpIniWalkMaxDepth bounds how deep the php-config scan recurses under a
// document root. Deep enough to reach payloads hidden in nested plugin,
// theme, and node_modules directories; bounded so the walk stays cheap.
const phpIniWalkMaxDepth = 6

// collectPHPIniFiles walks root up to maxDepth and returns every .user.ini and
// php.ini path found. No directory is skipped by name -- attackers hide these
// under node_modules and vendor trees -- so cost is bounded by depth alone.
func collectPHPIniFiles(root string, maxDepth int) []string {
	var out []string
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		entries, err := osFS.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			name := e.Name()
			full := filepath.Join(dir, name)
			if e.IsDir() {
				if depth > 0 {
					walk(full, depth-1)
				}
				continue
			}
			if name == ".user.ini" || name == "php.ini" {
				out = append(out, full)
			}
		}
	}
	walk(root, maxDepth)
	return out
}

// phpINISecurityBypass returns the strong, low-false-positive signals that a
// PHP ini file weakens security: disable_functions cleared or neutralized,
// allow_url_include enabled, or open_basedir removed. content must be
// lowercased. Used for newly-seen files, where the noisier per-function
// diffing of analyzePHPINI would flag benign partial disable lists.
func phpINISecurityBypass(content string) []string {
	var out []string
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		switch {
		case strings.HasPrefix(key, "disable_functions"):
			if disableFunctionsNeutralized(val) {
				out = append(out, "disable_functions cleared or neutralized (dangerous PHP functions enabled)")
			}
		case strings.HasPrefix(key, "allow_url_include"):
			if val == "on" || val == "1" {
				out = append(out, "allow_url_include enabled (remote code inclusion)")
			}
		case strings.HasPrefix(key, "open_basedir"):
			if val == "" || val == "/" {
				out = append(out, "open_basedir cleared (filesystem sandbox removed)")
			}
		}
	}
	return out
}

// disableFunctionsNeutralized reports whether a disable_functions value fails
// to actually disable any dangerous function -- empty, "none", or set to junk
// (the `disable_functions=ByPassed By 0xNix` camouflage). val must be
// lowercased and unquoted. A genuine hardening list always names at least one
// dangerous function, so the absence of every one means the directive disables
// nothing.
func disableFunctionsNeutralized(val string) bool {
	if val == "" || val == "none" {
		return true
	}
	for _, fn := range []string{"exec", "system", "shell_exec", "passthru", "proc_open", "popen", "eval", "assert", "pcntl"} {
		if strings.Contains(val, fn) {
			return false
		}
	}
	return true
}
