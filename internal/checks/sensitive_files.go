package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// sensitiveWatchset is the static set of system-configuration paths CSM
// raises a finding on when any of them is opened for write. The set is
// intentionally narrow and not operator-configurable: an attacker who
// learns that a path is excluded gets a free landing pad.
//
// Glob entries expand at runtime; non-glob entries appear once.
var sensitiveWatchset = []string{
	"/etc/shadow",
	"/etc/gshadow",
	"/etc/passwd",
	"/etc/group",
	"/etc/sudoers",
	"/etc/sudoers.d/*",
	"/etc/ssh/sshd_config",
	"/etc/ssh/sshd_config.d/*",
	"/etc/cron.d/*",
	"/etc/cron.hourly/*",
	"/etc/cron.daily/*",
	"/etc/cron.weekly/*",
	"/etc/cron.monthly/*",
	"/var/spool/cron/*",
}

const sensitiveFileBaselineKey = "_sensitive_file_hash:__baseline_complete"

// ExpandWatchset returns the absolute paths in the watchset, with globs
// expanded against the given filesystem root. Non-existent paths drop
// silently; the next refresh picks them up once they are created. root
// is "/" in production and a t.TempDir in tests.
func ExpandWatchset(root string) []string {
	var out []string
	for _, pat := range sensitiveWatchset {
		full := filepath.Join(root, pat)
		if strings.ContainsAny(pat, "*?[") {
			matches, _ := filepath.Glob(full)
			out = append(out, matches...)
			continue
		}
		out = append(out, full)
	}
	return out
}

// classifySensitive returns a stable kind label for a watchset path so
// findings can vary their severity and message.
func classifySensitive(path string) string {
	switch filepath.Base(path) {
	case "shadow", "gshadow", "passwd", "group":
		return "auth"
	case "sshd_config":
		return "sshd"
	case "sudoers":
		return "sudo"
	}
	dir := filepath.Dir(path)
	if strings.Contains(dir, "/cron") || strings.Contains(dir, "/spool/cron") {
		return "cron"
	}
	if strings.Contains(dir, "/sudoers.d") {
		return "sudo"
	}
	if strings.Contains(dir, "/sshd_config.d") {
		return "sshd"
	}
	return ""
}

// EvaluateSensitiveFileWrite returns a populated alert.Finding and true when
// the BPF live backend observed a write to a watchset path. Pure: no IO.
// Returns false for paths classifySensitive does not recognise -- the BPF
// program already filters via its dev+inode map, but this guards against
// stale map entries pointing at unrelated files.
func EvaluateSensitiveFileWrite(path string, uid, pid uint32, comm string) (alert.Finding, bool) {
	kind := classifySensitive(path)
	if kind == "" {
		return alert.Finding{}, false
	}
	sev := alert.High
	if uid != 0 {
		sev = alert.Critical
	}
	return alert.Finding{
		Severity: sev,
		Check:    "sensitive_file_modified",
		Message:  fmt.Sprintf("Write to sensitive system file: %s (uid=%d)", path, uid),
		Details:  fmt.Sprintf("Class: %s, PID: %d, Comm: %s, User: %s", kind, pid, comm, LookupUser(uid)),
	}, true
}

// EvaluateSensitiveFileAppearance returns a finding when a new file appears
// inside a sensitive glob directory between live watchset refreshes.
func EvaluateSensitiveFileAppearance(path string) (alert.Finding, bool) {
	kind := classifySensitive(path)
	if kind == "" {
		return alert.Finding{}, false
	}
	return alert.Finding{
		Severity: alert.High,
		Check:    "sensitive_file_modified",
		Message:  fmt.Sprintf("New sensitive system file appeared: %s", path),
		Details:  fmt.Sprintf("Class: %s", kind),
	}, true
}

// CheckSensitiveFiles is the periodic safety-net that runs when the BPF
// live monitor is unavailable or disabled. It content-hashes every watchset
// path and emits a finding when a hash differs from the previous run. The
// first run records baselines without emitting findings.
//
// CheckShadowChanges in auth.go does richer per-user diff and infra-IP
// suppression for /etc/shadow specifically; this catch-all complements
// that for sshd_config, sudoers, cron drop-ins, etc. Both run in parallel;
// audit-log dedup handles the (rare) overlap.
func CheckSensitiveFiles(_ context.Context, _ *config.Config, store *state.Store) []alert.Finding {
	if store == nil {
		return nil
	}
	var findings []alert.Finding
	_, baselineComplete := store.GetRaw(sensitiveFileBaselineKey)
	for _, path := range ExpandWatchset("/") {
		data, err := osFS.ReadFile(path)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(data)
		hashHex := hex.EncodeToString(sum[:])

		key := "_sensitive_file_hash:" + path
		prev, ok := store.GetRaw(key)
		if !ok {
			store.SetRaw(key, hashHex)
			if baselineComplete {
				if f, emit := EvaluateSensitiveFileAppearance(path); emit {
					findings = append(findings, f)
				}
			}
			continue
		}
		if prev == hashHex {
			continue
		}
		store.SetRaw(key, hashHex)
		findings = append(findings, alert.Finding{
			Severity:  alert.High,
			Check:     "sensitive_file_modified",
			Message:   fmt.Sprintf("Periodic check: content hash changed for %s", path),
			Details:   fmt.Sprintf("Previous: %s, Current: %s", prev, hashHex),
			FilePath:  path,
			Timestamp: time.Now(),
		})
	}
	if !baselineComplete {
		store.SetRaw(sensitiveFileBaselineKey, "1")
	}
	return findings
}
