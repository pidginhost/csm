package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// CheckPHPConfigChanges monitors .user.ini and .htaccess for PHP configuration
// changes that weaken security (disabling disable_functions, enabling dangerous functions).
// This runs as a deep check. The fanotify watcher also catches .user.ini writes in real-time.
func CheckPHPConfigChanges(ctx context.Context, _ *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	homeDirs, _ := GetScanHomeDirs()
	for _, homeEntry := range homeDirs {
		if !homeEntry.IsDir() {
			continue
		}
		user := homeEntry.Name()

		// Check .user.ini in public_html and addon domains
		iniPaths := []string{
			filepath.Join("/home", user, "public_html", ".user.ini"),
		}
		subDirs, _ := osFS.ReadDir(filepath.Join("/home", user))
		for _, sd := range subDirs {
			if sd.IsDir() && sd.Name() != "public_html" && sd.Name() != "mail" &&
				!strings.HasPrefix(sd.Name(), ".") && sd.Name() != "etc" &&
				sd.Name() != "logs" && sd.Name() != "ssl" && sd.Name() != "tmp" {
				iniPath := filepath.Join("/home", user, sd.Name(), ".user.ini")
				if _, err := osFS.Stat(iniPath); err == nil {
					iniPaths = append(iniPaths, iniPath)
				}
			}
		}

		for _, iniPath := range iniPaths {
			// Hash-based change detection
			hash, err := hashFileContent(iniPath)
			if err != nil {
				continue
			}

			key := "_phpini:" + iniPath
			prev, exists := store.GetRaw(key)
			store.SetRaw(key, hash)

			if !exists || prev == hash {
				continue
			}

			// File changed - analyze content for dangerous settings
			data, err := osFS.ReadFile(iniPath)
			if err != nil {
				continue
			}
			content := strings.ToLower(string(data))

			// Check for dangerous PHP settings
			dangerous := analyzePHPINI(content)
			if len(dangerous) > 0 {
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "php_config_change",
					Message:  fmt.Sprintf("Dangerous PHP config change: %s (user: %s)", iniPath, user),
					Details:  fmt.Sprintf("Dangerous settings:\n- %s", strings.Join(dangerous, "\n- ")),
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
