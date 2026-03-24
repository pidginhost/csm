package checks

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

// CheckFileIndex builds an index of PHP and executable files in /home,
// diffs against the previous index, and alerts on new suspicious files.
//
// This catches unknown webshell names that pattern-based checks miss.
// First run builds the baseline index. Subsequent runs diff and alert.
func CheckFileIndex(cfg *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	indexDir := cfg.StatePath
	currentPath := filepath.Join(indexDir, "fileindex.current")
	previousPath := filepath.Join(indexDir, "fileindex.previous")

	// Build current index using find (fast, low memory)
	// Index: PHP files in public_html, executables in .config
	currentEntries := buildFileIndex()

	// Write current index to disk
	writeIndex(currentPath, currentEntries)

	// If no previous index exists, this is the first run — just save and return
	if _, err := os.Stat(previousPath); os.IsNotExist(err) {
		copyFile(currentPath, previousPath)
		return nil
	}

	// Load previous index
	previousEntries := loadIndex(previousPath)

	// Diff: find entries in current that are NOT in previous
	prevSet := make(map[string]bool, len(previousEntries))
	for _, e := range previousEntries {
		prevSet[e] = true
	}

	var newFiles []string
	for _, e := range currentEntries {
		if !prevSet[e] {
			newFiles = append(newFiles, e)
		}
	}

	// Analyze new files for suspicious patterns
	for _, entry := range newFiles {
		// Parse entry: "path|size|mtime"
		parts := strings.SplitN(entry, "|", 3)
		if len(parts) < 1 {
			continue
		}
		path := parts[0]
		name := filepath.Base(path)
		nameLower := strings.ToLower(name)

		// Skip suppressed paths
		suppressed := false
		for _, ignore := range cfg.Suppressions.IgnorePaths {
			if matchGlob(path, ignore) {
				suppressed = true
				break
			}
		}
		if suppressed {
			continue
		}

		severity := alert.Severity(-1) // -1 = no alert
		check := ""
		message := ""

		// PHP files in uploads directories — should never appear normally
		if strings.Contains(path, "/wp-content/uploads/") && strings.HasSuffix(nameLower, ".php") {
			if isKnownSafeUpload(path, name) {
				continue
			}
			severity = alert.High
			check = "new_php_in_uploads"
			message = fmt.Sprintf("New PHP file in uploads: %s", path)
		}

		// Executables in .config directories
		if strings.Contains(path, "/.config/") {
			severity = alert.Critical
			check = "new_executable_in_config"
			message = fmt.Sprintf("New executable in .config: %s", path)
		}

		// Known webshell names (catches renames/variants too)
		if isWebshellName(nameLower) {
			severity = alert.Critical
			check = "new_webshell_file"
			message = fmt.Sprintf("New file with webshell name: %s", path)
		}

		// PHP files in theme/plugin dirs that weren't there before
		// Only flag if they have suspicious names
		if strings.HasSuffix(nameLower, ".php") && isSuspiciousPHPName(nameLower) {
			if severity < 0 {
				severity = alert.High
				check = "new_suspicious_php"
				message = fmt.Sprintf("New suspicious PHP file: %s", path)
			}
		}

		if severity >= 0 {
			details := ""
			if len(parts) >= 3 {
				details = fmt.Sprintf("Size: %s, Mtime: %s", parts[1], parts[2])
			}
			findings = append(findings, alert.Finding{
				Severity: severity,
				Check:    check,
				Message:  message,
				Details:  details,
			})
		}
	}

	// Update previous index for next run
	copyFile(currentPath, previousPath)

	return findings
}

// buildFileIndex uses find to collect PHP files and executables in relevant paths.
func buildFileIndex() []string {
	var entries []string

	// PHP files in all public_html directories (wp-content/uploads focus)
	out, _ := runCmd("find", "/home", "-maxdepth", "8",
		"-path", "*/wp-content/uploads/*.php",
		"-not", "-name", "index.php",
		"-type", "f",
		"-printf", "%p|%s|%T@\\n")
	if out != nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line != "" {
				entries = append(entries, line)
			}
		}
	}

	// Executables in .config directories (backdoor binary location)
	out, _ = runCmd("find", "/home", "-maxdepth", "5",
		"-path", "*/.config/*",
		"-type", "f",
		"-executable",
		"-printf", "%p|%s|%T@\\n")
	if out != nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line != "" {
				entries = append(entries, line)
			}
		}
	}

	// PHP files with suspicious names anywhere in public_html
	suspiciousNames := []string{
		"-name", "*.phtml",
		"-o", "-name", "*.pht",
		"-o", "-name", "*.php5",
		"-o", "-name", "*.haxor",
		"-o", "-name", "*.cgix",
	}
	args := append([]string{"/home", "-maxdepth", "6", "-type", "f", "("}, suspiciousNames...)
	args = append(args, ")", "-printf", "%p|%s|%T@\\n")
	out, _ = runCmd("find", args...)
	if out != nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line != "" {
				entries = append(entries, line)
			}
		}
	}

	sort.Strings(entries)
	return entries
}

func isKnownSafeUpload(path, name string) bool {
	safePaths := []string{
		"/cache/", "/imunify", "/redux/", "/mailchimp-for-wp/",
		"/sucuri/", "/smush/", "/goldish/", "/wpallexport/",
		"/wpallimport/", "/wph/", "/stm_fonts/", "/smile_fonts/",
		"/bws-custom-code/", "/wp-import-export-lite/",
		"/mc4wp-debug-log.php", "/zn_fonts/", "/companies_documents/",
	}
	if name == "index.php" {
		return true
	}
	for _, sp := range safePaths {
		if strings.Contains(path, sp) {
			return true
		}
	}
	return false
}

func isWebshellName(name string) bool {
	webshells := map[string]bool{
		"h4x0r.php": true, "c99.php": true, "r57.php": true,
		"wso.php": true, "alfa.php": true, "b374k.php": true,
		"shell.php": true, "cmd.php": true, "backdoor.php": true,
		"webshell.php": true, "hack.php": true, "0x.php": true,
		"up.php": true, "uploader.php": true, "filemanager.php": true,
	}
	return webshells[name]
}

func isSuspiciousPHPName(name string) bool {
	suspicious := []string{
		"shell", "cmd", "exec", "hack", "backdoor", "upload",
		"exploit", "reverse", "connect", "proxy", "tunnel",
		"0x", "x0", "eval", "assert", "passthru",
	}
	for _, s := range suspicious {
		if strings.Contains(name, s) {
			return true
		}
	}
	// Random-looking short names (e.g. x7y2z.php, ab12.php)
	nameNoExt := strings.TrimSuffix(name, ".php")
	if len(nameNoExt) <= 5 && strings.ContainsAny(nameNoExt, "0123456789") {
		return true
	}
	return false
}

func writeIndex(path string, entries []string) {
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	w := bufio.NewWriter(f)
	for _, e := range entries {
		_, _ = w.WriteString(e + "\n")
	}
	_ = w.Flush()
}

func loadIndex(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var entries []string
	scanner := bufio.NewScanner(f)
	// Increase buffer for long lines
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			entries = append(entries, line)
		}
	}
	return entries
}

func copyFile(src, dst string) {
	data, err := os.ReadFile(src)
	if err != nil {
		return
	}
	_ = os.WriteFile(dst, data, 0600)
}
