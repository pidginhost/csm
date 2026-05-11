package checks

import (
	"bytes"
	"fmt"
	"io"
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
	return FixErrorLogBloatInRoots(path, fixPerfAllowedRoots)
}

// FixErrorLogBloatInRoots is FixErrorLogBloat with caller-supplied roots.
// The Web UI uses this to include configured account_roots while tests can
// keep writes under t.TempDir().
func FixErrorLogBloatInRoots(path string, allowedRoots []string) RemediationResult {
	if path == "" {
		return RemediationResult{Error: "could not extract file path from finding"}
	}

	resolved, info, err := resolveExistingFixPath(path, allowedRoots)
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
	if err := truncateFilePreservingIdentity(resolved, info); err != nil {
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
	return FixDisplayErrorsOnInRoots(path, fixPerfAllowedRoots)
}

// FixDisplayErrorsOnInRoots is FixDisplayErrorsOn with caller-supplied
// roots. The Web UI uses this to honor account_roots outside /home.
func FixDisplayErrorsOnInRoots(path string, allowedRoots []string) RemediationResult {
	if path == "" {
		return RemediationResult{Error: "could not extract file path from finding"}
	}

	resolved, info, err := resolveExistingFixPath(path, allowedRoots)
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
	// the supplied remediation roots; symlinks already rejected.
	data, err := readFilePreservingIdentity(resolved, info)
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
	if err := writeFilePreservingOwner(resolved, rewritten, info); err != nil {
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
	for _, raw := range bytes.SplitAfter(data, []byte("\n")) {
		if len(raw) == 0 {
			continue
		}
		line := raw
		newline := []byte(nil)
		if bytes.HasSuffix(raw, []byte("\n")) {
			line = raw[:len(raw)-1]
			newline = []byte("\n")
		}
		lineText := string(line)
		trimmed := strings.TrimSpace(lineText)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			out.Write(raw)
			continue
		}
		if !strings.Contains(strings.ToLower(trimmed), "display_errors") {
			out.Write(raw)
			continue
		}
		out.WriteString("# csm: disabled by remediation -- ")
		out.WriteString(lineText)
		out.Write(newline)
		changed++
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

// These helpers re-check the target inode after the initial path validation
// so a file swap between validation and mutation fails closed.
func truncateFilePreservingIdentity(path string, expected os.FileInfo) error {
	f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !sameFileIdentity(info, expected) {
		return fmt.Errorf("file changed during remediation")
	}
	return f.Truncate(0)
}

func readFilePreservingIdentity(path string, expected os.FileInfo) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !sameFileIdentity(info, expected) {
		return nil, fmt.Errorf("file changed during remediation")
	}
	return io.ReadAll(f)
}

func writeFilePreservingOwner(path string, data []byte, original os.FileInfo) error {
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
	if merr := os.Chmod(tmpPath, original.Mode().Perm()); merr != nil {
		cleanup()
		return fmt.Errorf("chmod temp: %v", merr)
	}
	info, statErr := os.Lstat(path)
	if statErr != nil {
		cleanup()
		return fmt.Errorf("stat original: %v", statErr)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		cleanup()
		return fmt.Errorf("original became a symlink during remediation")
	}
	if !sameFileIdentity(info, original) {
		cleanup()
		return fmt.Errorf("file changed during remediation")
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

func sameFileIdentity(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return false
	}
	if os.SameFile(a, b) {
		return true
	}
	as, aok := a.Sys().(*syscall.Stat_t)
	bs, bok := b.Sys().(*syscall.Stat_t)
	return aok && bok && as.Dev == bs.Dev && as.Ino == bs.Ino
}
