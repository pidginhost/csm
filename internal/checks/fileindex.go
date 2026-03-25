package checks

import (
	"bufio"
	"encoding/json"
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

// dirMtimeCache maps directory paths to their last-known mtime (unix seconds).
// Directories with unchanged mtime are skipped during scanning.
type dirMtimeCache map[string]int64

func loadDirCache(stateDir string) dirMtimeCache {
	cache := make(dirMtimeCache)
	data, err := os.ReadFile(filepath.Join(stateDir, "dircache.json"))
	if err == nil {
		_ = json.Unmarshal(data, &cache)
	}
	return cache
}

func saveDirCache(stateDir string, cache dirMtimeCache) {
	data, _ := json.Marshal(cache)
	tmpPath := filepath.Join(stateDir, "dircache.json.tmp")
	_ = os.WriteFile(tmpPath, data, 0600)
	_ = os.Rename(tmpPath, filepath.Join(stateDir, "dircache.json"))
}

// dirChanged returns true if the directory mtime has changed since last scan.
// Updates the cache with the new mtime.
func dirChanged(dir string, cache dirMtimeCache) bool {
	info, err := os.Stat(dir)
	if err != nil {
		return true // can't stat, scan it to be safe
	}
	mtime := info.ModTime().Unix()
	prev, exists := cache[dir]
	cache[dir] = mtime
	if !exists {
		return true // first time seeing this dir
	}
	return mtime != prev
}

// CheckFileIndex builds an index of suspicious files using pure Go directory
// reads, diffs against the previous index, and alerts on new files.
// Uses directory mtime caching: unchanged dirs carry forward previous entries
// without calling ReadDir, while changed dirs are re-scanned.
func CheckFileIndex(cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	indexDir := cfg.StatePath
	currentPath := filepath.Join(indexDir, "fileindex.current")
	previousPath := filepath.Join(indexDir, "fileindex.previous")

	// Load caches
	dirCache := loadDirCache(indexDir)

	// Build a set of previous entries grouped by their top-level scan dir,
	// so unchanged dirs can carry forward their entries without ReadDir.
	previousEntries := loadIndex(previousPath)
	prevByDir := groupEntriesByUploadDir(previousEntries)

	// Build current index
	currentEntries := buildFileIndex(dirCache, prevByDir)

	// Save updated dir cache
	saveDirCache(indexDir, dirCache)

	// Write current index (atomic)
	writeIndex(currentPath, currentEntries)

	// First run — save baseline
	if _, err := os.Stat(previousPath); os.IsNotExist(err) {
		copyFile(currentPath, previousPath)
		return nil
	}

	// Validate index
	if len(previousEntries) > 10 && len(currentEntries) == 0 {
		fmt.Fprintf(os.Stderr, "file_index: current index empty but previous had %d entries, skipping diff\n", len(previousEntries))
		return nil
	}
	if len(previousEntries) > 0 && len(currentEntries) < len(previousEntries)/2 {
		fmt.Fprintf(os.Stderr, "file_index: current index (%d) < half of previous (%d), skipping diff\n", len(currentEntries), len(previousEntries))
		return nil
	}

	// Diff
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

	// Analyze new files — lazy stat only for alerting
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

		if strings.Contains(path, "/wp-content/uploads/") && strings.HasSuffix(nameLower, ".php") {
			if isKnownSafeUpload(path, name) {
				continue
			}
			severity = alert.High
			check = "new_php_in_uploads"
			message = fmt.Sprintf("New PHP file in uploads: %s", path)
		}

		// PHP files in wp-content/languages — should only contain .mo/.po/.l10n.php
		if strings.Contains(path, "/wp-content/languages/") && strings.HasSuffix(nameLower, ".php") {
			if !strings.HasSuffix(nameLower, ".l10n.php") && nameLower != "index.php" {
				severity = alert.Critical
				check = "new_php_in_languages"
				message = fmt.Sprintf("New PHP file in wp-content/languages (should only contain translations): %s", path)
			}
		}

		// PHP files in wp-content/upgrade — should be empty except index.php
		if strings.Contains(path, "/wp-content/upgrade/") && strings.HasSuffix(nameLower, ".php") {
			if nameLower != "index.php" {
				severity = alert.Critical
				check = "new_php_in_upgrade"
				message = fmt.Sprintf("New PHP file in wp-content/upgrade (should be empty): %s", path)
			}
		}

		if strings.Contains(path, "/.config/") {
			severity = alert.Critical
			check = "new_executable_in_config"
			message = fmt.Sprintf("New executable in .config: %s", path)
		}

		if isWebshellName(nameLower) {
			severity = alert.Critical
			check = "new_webshell_file"
			message = fmt.Sprintf("New file with webshell name: %s", path)
		}

		if strings.HasSuffix(nameLower, ".php") && isSuspiciousPHPName(nameLower) {
			if severity < 0 {
				severity = alert.High
				check = "new_suspicious_php"
				message = fmt.Sprintf("New suspicious PHP file: %s", path)
			}
		}

		if severity >= 0 {
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

	copyFile(currentPath, previousPath)
	return findings
}

// groupEntriesByUploadDir groups index entries by their containing scan root.
// Used to carry forward entries from unchanged directories.
func groupEntriesByUploadDir(entries []string) map[string][]string {
	grouped := make(map[string][]string)
	for _, path := range entries {
		// Find the scan root: uploads dir, .config dir, or tmp dir
		dir := filepath.Dir(path)
		grouped[dir] = append(grouped[dir], path)
	}
	return grouped
}

// buildFileIndex scans targeted directory subtrees using ReadDir.
// Skips directories whose mtime hasn't changed — carries forward
// their entries from the previous index instead.
func buildFileIndex(dirCache dirMtimeCache, prevByDir map[string][]string) []string {
	var entries []string

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

		// Scan wp-content/uploads for PHP files
		uploadDirs := []string{
			filepath.Join(homeDir, "public_html", "wp-content", "uploads"),
		}
		// Scan directories that shouldn't normally contain user PHP:
		// languages (translation files only), upgrade (temp dir), mu-plugins
		sensitiveWPDirs := []string{
			filepath.Join(homeDir, "public_html", "wp-content", "languages"),
			filepath.Join(homeDir, "public_html", "wp-content", "upgrade"),
			filepath.Join(homeDir, "public_html", "wp-content", "mu-plugins"),
		}
		subDirs, _ := os.ReadDir(homeDir)
		for _, sd := range subDirs {
			if sd.IsDir() && sd.Name() != "public_html" && sd.Name() != "mail" &&
				!strings.HasPrefix(sd.Name(), ".") && sd.Name() != "etc" &&
				sd.Name() != "logs" && sd.Name() != "ssl" && sd.Name() != "tmp" {
				uploadsPath := filepath.Join(homeDir, sd.Name(), "wp-content", "uploads")
				if info, err := os.Stat(uploadsPath); err == nil && info.IsDir() {
					uploadDirs = append(uploadDirs, uploadsPath)
				}
				// Also track sensitive dirs for addon domains
				for _, subDir := range []string{"languages", "upgrade", "mu-plugins"} {
					sensitiveDir := filepath.Join(homeDir, sd.Name(), "wp-content", subDir)
					if info, err := os.Stat(sensitiveDir); err == nil && info.IsDir() {
						sensitiveWPDirs = append(sensitiveWPDirs, sensitiveDir)
					}
				}
			}
		}

		for _, uploadsDir := range uploadDirs {
			scanDirForPHP(uploadsDir, 6, dirCache, prevByDir, &entries)
		}

		// Scan sensitive WP directories for any PHP files
		for _, sensitiveDir := range sensitiveWPDirs {
			scanDirForPHP(sensitiveDir, 4, dirCache, prevByDir, &entries)
		}

		// Scan .config for executables
		configDir := filepath.Join(homeDir, ".config")
		scanDirForExecutables(configDir, 3, dirCache, prevByDir, &entries)
	}

	// Scan tmp dirs
	for _, tmpDir := range []string{"/tmp", "/dev/shm", "/var/tmp"} {
		scanDirForSuspiciousExt(tmpDir, 2, dirCache, prevByDir, &entries)
	}

	sort.Strings(entries)
	return entries
}

// scanDirForPHP recursively reads directories for .php files.
// If directory mtime is unchanged, carries forward previous entries.
func scanDirForPHP(dir string, maxDepth int, cache dirMtimeCache, prev map[string][]string, entries *[]string) {
	if maxDepth <= 0 {
		return
	}

	if !dirChanged(dir, cache) {
		// Carry forward previous entries for this directory
		*entries = append(*entries, prev[dir]...)
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
			scanDirForPHP(fullPath, maxDepth-1, cache, prev, entries)
			continue
		}

		nameLower := strings.ToLower(name)
		if strings.HasSuffix(nameLower, ".php") && nameLower != "index.php" {
			*entries = append(*entries, fullPath)
		}
		ext := filepath.Ext(nameLower)
		if suspiciousExtensions[ext] {
			*entries = append(*entries, fullPath)
		}
	}
}

// scanDirForExecutables reads .config dirs for executable files.
func scanDirForExecutables(dir string, maxDepth int, cache dirMtimeCache, prev map[string][]string, entries *[]string) {
	if maxDepth <= 0 {
		return
	}
	if !dirChanged(dir, cache) {
		*entries = append(*entries, prev[dir]...)
		return
	}

	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range dirEntries {
		fullPath := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			scanDirForExecutables(fullPath, maxDepth-1, cache, prev, entries)
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.Mode()&0111 != 0 {
			*entries = append(*entries, fullPath)
		}
	}
}

// scanDirForSuspiciousExt reads tmp dirs for files with suspicious extensions.
func scanDirForSuspiciousExt(dir string, maxDepth int, cache dirMtimeCache, prev map[string][]string, entries *[]string) {
	if maxDepth <= 0 {
		return
	}
	if !dirChanged(dir, cache) {
		*entries = append(*entries, prev[dir]...)
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
			scanDirForSuspiciousExt(fullPath, maxDepth-1, cache, prev, entries)
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
