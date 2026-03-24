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

// suspiciousExtensions are file extensions that should never appear in web roots.
var suspiciousExtensions = map[string]bool{
	".phtml": true, ".pht": true, ".php5": true,
	".haxor": true, ".cgix": true,
}

// CheckFileIndex builds an index of suspicious files using pure Go directory
// reads (os.ReadDir / getdents syscall), diffs against the previous index,
// and alerts on new suspicious files.
//
// This is much faster than `find` because:
// - os.ReadDir uses getdents (reads dir entries without stat per file)
// - We only stat() the small subset of files that match our patterns
// - We only scan known-dangerous directory subtrees, not all of /home
func CheckFileIndex(cfg *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	indexDir := cfg.StatePath
	currentPath := filepath.Join(indexDir, "fileindex.current")
	previousPath := filepath.Join(indexDir, "fileindex.previous")

	// Build current index using pure Go ReadDir (no find)
	currentEntries := buildFileIndex()

	// Write current index to disk (atomic)
	writeIndex(currentPath, currentEntries)

	// First run — save baseline and return
	if _, err := os.Stat(previousPath); os.IsNotExist(err) {
		copyFile(currentPath, previousPath)
		return nil
	}

	// Validate: skip diff if current index looks broken
	previousEntries := loadIndex(previousPath)
	if len(previousEntries) > 10 && len(currentEntries) == 0 {
		fmt.Fprintf(os.Stderr, "file_index: current index empty but previous had %d entries, skipping diff\n", len(previousEntries))
		return nil
	}
	if len(previousEntries) > 0 && len(currentEntries) < len(previousEntries)/2 {
		fmt.Fprintf(os.Stderr, "file_index: current index (%d) < half of previous (%d), skipping diff\n", len(currentEntries), len(previousEntries))
		return nil
	}

	// Diff: find paths in current that are NOT in previous
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

	// Analyze new files — only stat these (tiny subset)
	for _, path := range newFiles {
		name := filepath.Base(path)
		nameLower := strings.ToLower(name)

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

		severity := alert.Severity(-1)
		check := ""
		message := ""

		// PHP in uploads
		if strings.Contains(path, "/wp-content/uploads/") && strings.HasSuffix(nameLower, ".php") {
			if isKnownSafeUpload(path, name) {
				continue
			}
			severity = alert.High
			check = "new_php_in_uploads"
			message = fmt.Sprintf("New PHP file in uploads: %s", path)
		}

		// Executables in .config
		if strings.Contains(path, "/.config/") {
			severity = alert.Critical
			check = "new_executable_in_config"
			message = fmt.Sprintf("New executable in .config: %s", path)
		}

		// Known webshell names
		if isWebshellName(nameLower) {
			severity = alert.Critical
			check = "new_webshell_file"
			message = fmt.Sprintf("New file with webshell name: %s", path)
		}

		// Suspicious PHP names
		if strings.HasSuffix(nameLower, ".php") && isSuspiciousPHPName(nameLower) {
			if severity < 0 {
				severity = alert.High
				check = "new_suspicious_php"
				message = fmt.Sprintf("New suspicious PHP file: %s", path)
			}
		}

		if severity >= 0 {
			// Lazy stat — only for files we're alerting on
			details := ""
			if info, err := os.Stat(path); err == nil {
				details = fmt.Sprintf("Size: %d, Mtime: %s", info.Size(), info.ModTime().Format("2006-01-02 15:04:05"))
			}
			findings = append(findings, alert.Finding{
				Severity: severity,
				Check:    check,
				Message:  message,
				Details:  details,
			})
		}
	}

	// Update previous index
	copyFile(currentPath, previousPath)

	return findings
}

// buildFileIndex uses pure Go os.ReadDir (getdents syscall) to scan
// targeted directories. No external commands, no stat per file.
func buildFileIndex() []string {
	var entries []string

	// Get all home directories
	homeDirs, err := os.ReadDir("/home")
	if err != nil {
		return nil
	}

	for _, homeEntry := range homeDirs {
		if !homeEntry.IsDir() {
			continue
		}
		user := homeEntry.Name()
		homeDir := filepath.Join("/home", user)

		// 1. Scan wp-content/uploads for PHP files
		// Check multiple possible document root patterns
		uploadDirs := []string{
			filepath.Join(homeDir, "public_html", "wp-content", "uploads"),
		}
		// Also check addon domains (one level deep)
		subDirs, _ := os.ReadDir(homeDir)
		for _, sd := range subDirs {
			if sd.IsDir() && sd.Name() != "public_html" && sd.Name() != "mail" &&
				!strings.HasPrefix(sd.Name(), ".") && sd.Name() != "etc" &&
				sd.Name() != "logs" && sd.Name() != "ssl" && sd.Name() != "tmp" {
				uploadsPath := filepath.Join(homeDir, sd.Name(), "wp-content", "uploads")
				if info, err := os.Stat(uploadsPath); err == nil && info.IsDir() {
					uploadDirs = append(uploadDirs, uploadsPath)
				}
			}
		}

		for _, uploadsDir := range uploadDirs {
			scanDirForPHP(uploadsDir, 6, &entries)
		}

		// 2. Scan .config for executables
		configDir := filepath.Join(homeDir, ".config")
		scanDirForExecutables(configDir, 3, &entries)
	}

	// 3. Scan /tmp and /dev/shm for suspicious extensions
	for _, tmpDir := range []string{"/tmp", "/dev/shm", "/var/tmp"} {
		scanDirForSuspiciousExt(tmpDir, 2, &entries)
	}

	sort.Strings(entries)
	return entries
}

// scanDirForPHP recursively reads directories looking for .php files.
// Uses os.ReadDir (getdents) — only stats files with .php extension.
func scanDirForPHP(dir string, maxDepth int, entries *[]string) {
	if maxDepth <= 0 {
		return
	}

	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range dirEntries {
		name := entry.Name()
		fullPath := filepath.Join(dir, name)

		if entry.IsDir() {
			scanDirForPHP(fullPath, maxDepth-1, entries)
			continue
		}

		nameLower := strings.ToLower(name)

		// PHP files (not index.php)
		if strings.HasSuffix(nameLower, ".php") && nameLower != "index.php" {
			*entries = append(*entries, fullPath)
		}

		// Suspicious extensions
		ext := filepath.Ext(nameLower)
		if suspiciousExtensions[ext] {
			*entries = append(*entries, fullPath)
		}
	}
}

// scanDirForExecutables reads .config dirs for executable files.
// Only stats files to check the executable bit (needed, but only in .config).
func scanDirForExecutables(dir string, maxDepth int, entries *[]string) {
	if maxDepth <= 0 {
		return
	}

	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range dirEntries {
		fullPath := filepath.Join(dir, entry.Name())

		if entry.IsDir() {
			scanDirForExecutables(fullPath, maxDepth-1, entries)
			continue
		}

		// Need to stat to check executable bit
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.Mode()&0111 != 0 { // any execute bit set
			*entries = append(*entries, fullPath)
		}
	}
}

// scanDirForSuspiciousExt reads tmp dirs for files with suspicious extensions.
func scanDirForSuspiciousExt(dir string, maxDepth int, entries *[]string) {
	if maxDepth <= 0 {
		return
	}

	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range dirEntries {
		name := entry.Name()
		fullPath := filepath.Join(dir, name)

		if entry.IsDir() {
			scanDirForSuspiciousExt(fullPath, maxDepth-1, entries)
			continue
		}

		ext := filepath.Ext(strings.ToLower(name))
		if suspiciousExtensions[ext] {
			*entries = append(*entries, fullPath)
		}
	}
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
	nameNoExt := strings.TrimSuffix(name, ".php")
	if len(nameNoExt) <= 5 && strings.ContainsAny(nameNoExt, "0123456789") {
		return true
	}
	return false
}

func writeIndex(path string, entries []string) {
	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return
	}

	w := bufio.NewWriter(f)
	for _, e := range entries {
		_, _ = w.WriteString(e + "\n")
	}
	_ = w.Flush()
	_ = f.Close()

	// Atomic rename
	_ = os.Rename(tmpPath, path)
}

func loadIndex(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var entries []string
	scanner := bufio.NewScanner(f)
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
