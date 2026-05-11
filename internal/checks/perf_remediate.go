package checks

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// fixPerfAllowedRoots scopes performance remediations to per-account web
// content. Same shape as the other fix*AllowedRoots so tests can swap in
// a t.TempDir().
var fixPerfAllowedRoots = []string{"/home"}

// FixErrorLogBloat truncates an account-owned error_log file in place.
// Truncating preserves the inode and file ownership so any PHP process
// holding the descriptor keeps appending to the same file without an
// open/reopen race; this is also the safest action because nothing in
// the host needs the historical lines to keep serving traffic.
func FixErrorLogBloat(path string) RemediationResult {
	if path == "" {
		return RemediationResult{Error: "could not extract file path from finding"}
	}

	resolved, info, err := resolveExistingFixPath(path, fixPerfAllowedRoots)
	if err != nil {
		return RemediationResult{Error: err.Error()}
	}
	if info.IsDir() {
		return RemediationResult{Error: "refusing to truncate a directory"}
	}
	if filepath.Base(resolved) != "error_log" {
		return RemediationResult{Error: fmt.Sprintf("refusing to truncate non error_log file: %s", resolved)}
	}

	oldSize := info.Size()
	if err := os.Truncate(resolved, 0); err != nil {
		return RemediationResult{Error: fmt.Sprintf("truncate failed: %v", err)}
	}

	return RemediationResult{
		Success:     true,
		Action:      fmt.Sprintf("truncate %s", resolved),
		Description: fmt.Sprintf("Emptied error_log (was %s)", humanBytes(oldSize)),
	}
}

// FixDisplayErrorsOn rewrites an INI / .htaccess / .user.ini file so the
// display_errors directive is set to Off. The original line is preserved
// commented out for operator review; an override line is appended at the
// end of the file so the last-write-wins semantics of every supported
// config format land on Off regardless of earlier statements.
//
// Only .user.ini, php.ini, and .htaccess are accepted. wp-config.php and
// other PHP source files require code-level edits this routine does not
// attempt. The caller (web UI) should not advertise the fix for those.
func FixDisplayErrorsOn(path string) RemediationResult {
	if path == "" {
		return RemediationResult{Error: "could not extract file path from finding"}
	}

	resolved, info, err := resolveExistingFixPath(path, fixPerfAllowedRoots)
	if err != nil {
		return RemediationResult{Error: err.Error()}
	}
	if info.IsDir() {
		return RemediationResult{Error: "refusing to edit a directory"}
	}

	base := filepath.Base(resolved)
	var (
		isHtaccess bool
		supported  bool
	)
	switch {
	case base == ".user.ini" || base == "php.ini" || strings.HasSuffix(base, ".ini"):
		supported = true
	case base == ".htaccess":
		supported = true
		isHtaccess = true
	}
	if !supported {
		return RemediationResult{Error: fmt.Sprintf("automated display_errors fix only supports .user.ini, php.ini, and .htaccess (got %s)", base)}
	}

	// #nosec G304 -- path was validated by resolveExistingFixPath against
	// fixPerfAllowedRoots; symlinks already rejected.
	data, err := os.ReadFile(resolved)
	if err != nil {
		return RemediationResult{Error: fmt.Sprintf("read failed: %v", err)}
	}

	rewritten, changedLines := commentDisplayErrorsLines(data)
	if changedLines == 0 {
		return RemediationResult{Error: "no display_errors directive found in file"}
	}

	if isHtaccess {
		rewritten = appendHtaccessOverride(rewritten)
	} else {
		rewritten = appendIniOverride(rewritten)
	}

	// Preserve ownership + mode. Write atomically via a sibling temp file +
	// rename so a partial write does not leave the operator with a broken
	// config.
	if err := writeFilePreservingOwner(resolved, rewritten, info.Mode().Perm()); err != nil {
		return RemediationResult{Error: err.Error()}
	}

	return RemediationResult{
		Success: true,
		Action:  fmt.Sprintf("disable display_errors in %s", resolved),
		Description: fmt.Sprintf(
			"Commented %d display_errors line(s) and appended an Off override at end of file",
			changedLines,
		),
	}
}

// commentDisplayErrorsLines walks the file line-by-line, comments out any
// non-comment line whose directive is display_errors (matching the
// detector's logic). Returns the rewritten bytes and the count of lines
// changed.
func commentDisplayErrorsLines(data []byte) ([]byte, int) {
	var out bytes.Buffer
	changed := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	// Allow long lines; .htaccess values can be wider than the default 64KiB.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	first := true
	for scanner.Scan() {
		line := scanner.Text()
		if !first {
			out.WriteByte('\n')
		}
		first = false
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			out.WriteString(line)
			continue
		}
		if !strings.Contains(strings.ToLower(trimmed), "display_errors") {
			out.WriteString(line)
			continue
		}
		out.WriteString("# csm: disabled by remediation -- ")
		out.WriteString(line)
		changed++
	}
	// Preserve the trailing newline if the original had one so editors do
	// not flag the file as missing the final newline.
	if len(data) > 0 && data[len(data)-1] == '\n' {
		out.WriteByte('\n')
	}
	return out.Bytes(), changed
}

func appendIniOverride(data []byte) []byte {
	override := "display_errors = Off"
	return appendOverrideLine(data, override, "; csm: appended by remediation")
}

func appendHtaccessOverride(data []byte) []byte {
	override := "php_flag display_errors Off"
	return appendOverrideLine(data, override, "# csm: appended by remediation")
}

func appendOverrideLine(data []byte, directive, marker string) []byte {
	var out bytes.Buffer
	out.Write(data)
	if len(data) > 0 && data[len(data)-1] != '\n' {
		out.WriteByte('\n')
	}
	out.WriteString(marker)
	out.WriteByte('\n')
	out.WriteString(directive)
	out.WriteByte('\n')
	return out.Bytes()
}

// writeFilePreservingOwner replaces a file via a same-directory temp file
// + rename. Original UID/GID/mode are copied onto the new file before the
// rename so the cPanel-owned config does not flip to root after the
// remediation runs. The rename is atomic on the same filesystem, so a
// crash mid-write leaves the original file intact.
func writeFilePreservingOwner(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, createErr := os.CreateTemp(dir, ".csm-perf-fix-*")
	if createErr != nil {
		return fmt.Errorf("create temp: %v", createErr)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, werr := tmp.Write(data); werr != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write temp: %v", werr)
	}
	if cerr := tmp.Close(); cerr != nil {
		cleanup()
		return fmt.Errorf("close temp: %v", cerr)
	}
	if merr := os.Chmod(tmpPath, mode); merr != nil {
		cleanup()
		return fmt.Errorf("chmod temp: %v", merr)
	}
	info, statErr := os.Lstat(path)
	if statErr != nil {
		cleanup()
		return fmt.Errorf("stat original: %v", statErr)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if chownErr := os.Chown(tmpPath, int(stat.Uid), int(stat.Gid)); chownErr != nil {
			cleanup()
			return fmt.Errorf("chown temp: %v", chownErr)
		}
	}
	if renameErr := os.Rename(tmpPath, path); renameErr != nil {
		cleanup()
		return fmt.Errorf("rename: %v", renameErr)
	}
	return nil
}
