package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
// the BPF live backend observed a write to a watchset path. It reads current
// content for content-bound self-write suppression.
// Returns false for paths classifySensitive does not recognise -- the BPF
// program already filters via its dev+inode map, but this guards against
// stale map entries pointing at unrelated files.
func EvaluateSensitiveFileWrite(path string, uid, pid uint32, comm string) (alert.Finding, bool) {
	content, err := osFS.ReadFile(path)
	return EvaluateSensitiveFileWriteSnapshot(path, uid, pid, comm, content, err == nil)
}

// EvaluateSensitiveFileWriteSnapshot evaluates a live write against bytes
// captured with the file state that will be recorded for refresh deduplication.
// Keeping those two observations together prevents a concurrent rename from
// making the finding describe or suppress different content.
func EvaluateSensitiveFileWriteSnapshot(path string, uid, pid uint32, comm string, content []byte, contentKnown bool) (alert.Finding, bool) {
	kind := classifySensitive(path)
	if kind == "" {
		return alert.Finding{}, false
	}
	// Suppress writes CSM itself just performed (e.g. installing a per-user
	// wp-cron). Content-bound: a tamper layered on top changes the hash and
	// is still reported.
	if contentKnown && isExpectedSelfWrite(path, content) {
		return alert.Finding{}, false
	}
	// Durable complement to the TTL-bounded self-write ledger: a user crontab
	// holding only CSM-installed WP-Cron jobs is CSM's own managed block, not
	// attacker persistence, even after a restart cleared the ledger.
	if suppressedAsManagedWPCron(path, content) {
		return alert.Finding{}, false
	}
	sev := alert.High
	if uid != 0 {
		sev = alert.Critical
	}
	f := alert.Finding{
		Severity: sev,
		Check:    "sensitive_file_modified",
		Message:  fmt.Sprintf("Write to sensitive system file: %s (uid=%d)", path, uid),
		Details:  fmt.Sprintf("Class: %s, PID: %d, Comm: %s, User: %s", kind, pid, comm, LookupUser(uid)),
		FilePath: path,
	}
	return rescoreSensitive(f, kind, nil, pid, time.Now()), true
}

// EvaluateSensitiveFileAppearance returns a finding when a path no previous
// watchset refresh had seen shows up -- a genuinely new cron drop-in, sudoers
// fragment, or user crontab.
func EvaluateSensitiveFileAppearance(path string) (alert.Finding, bool) {
	content, err := osFS.ReadFile(path)
	return evaluateSensitiveWatchsetChange(path, "New sensitive system file appeared", content, err == nil)
}

// evaluateSensitiveWatchsetChange builds the finding both refresh-diff outcomes
// share. Callers pass the bytes that produced the compared digest so a later
// rewrite cannot change self-write suppression or cron-content scoring.
func evaluateSensitiveWatchsetChange(path, summary string, content []byte, contentKnown bool) (alert.Finding, bool) {
	kind := classifySensitive(path)
	if kind == "" {
		return alert.Finding{}, false
	}
	if contentKnown {
		if isExpectedSelfWrite(path, content) {
			return alert.Finding{}, false
		}
	}
	if suppressedAsManagedWPCron(path, content) {
		return alert.Finding{}, false
	}
	now := time.Now()
	f := alert.Finding{
		Severity:  alert.High,
		Check:     "sensitive_file_modified",
		Message:   fmt.Sprintf("%s: %s", summary, path),
		Details:   fmt.Sprintf("Class: %s", kind),
		FilePath:  path,
		Timestamp: now,
	}
	var scoreContent []byte
	if kind == "cron" {
		scoreContent = content
	}
	return rescoreSensitive(f, kind, scoreContent, 0, now), true
}

// SensitiveFileState is the stable identity of one watchset path. Regular-file
// inode churn is deliberately excluded, while security metadata and symlink
// targets remain visible.
type SensitiveFileState struct {
	ContentDigest string
	PathIdentity  string
}

const sensitiveRegularPathIdentityPrefix = "type\x000"

// NextSensitiveDigests builds the state snapshot for a refresh cycle and
// returns the exact readable regular-file content behind each digest. A path
// whose content cannot be read keeps its previous digest so a transient read
// error does not surface as a content change. Non-regular objects retain type
// identity without being read. Paths absent from paths drop out. prev is only
// read and is never mutated.
func NextSensitiveDigests(prev map[string]SensitiveFileState, paths []string) (map[string]SensitiveFileState, map[string][]byte) {
	next := make(map[string]SensitiveFileState, len(paths))
	contents := make(map[string][]byte, len(paths))
	for _, path := range paths {
		state := prev[path]
		identity, regularContent, identityKnown := sensitivePathIdentity(path)
		if identityKnown {
			state.PathIdentity = identity
		}
		if !regularContent {
			next[path] = state
			continue
		}
		data, err := readSensitiveRegularFile(path)
		if err == nil {
			sum := sha256.Sum256(data)
			state.ContentDigest = hex.EncodeToString(sum[:])
			contents[path] = data
		}
		next[path] = state
	}
	return next, contents
}

type sensitiveRegularFileReader interface {
	ReadRegularFile(string) ([]byte, error)
}

// Production uses a nonblocking, fd-verified read. The fallback keeps custom
// test providers source-compatible after the preceding type check.
func readSensitiveRegularFile(path string) ([]byte, error) {
	if reader, ok := osFS.(sensitiveRegularFileReader); ok {
		return reader.ReadRegularFile(path)
	}
	return osFS.ReadFile(path)
}

func sensitivePathIdentity(path string) (identity string, regularContent, ok bool) {
	info, err := osFS.Lstat(path)
	if err != nil {
		return "", false, false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := osFS.Readlink(path)
		if err != nil {
			return "", false, false
		}
		targetInfo, err := osFS.Stat(path)
		if err != nil {
			return "symlink\x00" + target + "\x00unresolved", false, true
		}
		resolvedIdentity, regular := sensitiveResolvedIdentity(targetInfo)
		return "symlink\x00" + target + "\x00" + resolvedIdentity, regular, true
	}
	identity, regular := sensitiveResolvedIdentity(info)
	return identity, regular, true
}

func sensitiveResolvedIdentity(info os.FileInfo) (string, bool) {
	modeType := info.Mode() & os.ModeType
	identity := fmt.Sprintf("type\x00%x\x00perm\x00%o", modeType, info.Mode().Perm())
	if uid, gid, ok := sensitiveFileOwnership(info); ok {
		identity += fmt.Sprintf("\x00owner\x00%d\x00%d", uid, gid)
	}
	if modeType == 0 {
		return identity, true
	}
	if fileIdentity, ok := selfWriteIdentityFromFileInfo(info); ok {
		identity += fmt.Sprintf("\x00%d\x00%d", fileIdentity.Device, fileIdentity.Inode)
	}
	return identity, false
}

// DiffSensitiveWatchset compares two refresh snapshots of the watchset and
// returns the findings the newer one warrants. Both maps are keyed by
// absolute path. contents holds the bytes used for cur's content digests.
//
// Identity is the path, never the inode. Keying on dev+inode reported every
// atomic rewrite (write temp, rename over) as a brand-new file, which is how
// /etc/passwd came to "appear" 16 times in a month on a live host. A path the
// previous snapshot knew about can only have changed, not appeared.
//
// Paths that vanished produce nothing: the caller unwatches the inode, and a
// deletion is not evidence of the tampering this watchset exists to catch.
//
// liveReported holds the exact states whose live-hook findings were delivered
// since the last refresh. A matching state is adopted without a duplicate.
// An appearance is still reported: the hook describes a write, not the fact
// that the path did not exist before.
func DiffSensitiveWatchset(prev, cur map[string]SensitiveFileState, contents map[string][]byte, liveReported map[string]SensitiveFileState) []alert.Finding {
	paths := make([]string, 0, len(cur))
	for path := range cur {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	var findings []alert.Finding
	for _, path := range paths {
		curState := cur[path]
		prevState, known := prev[path]
		content, contentKnown := contents[path]
		switch {
		case !known:
			if f, emit := evaluateSensitiveWatchsetChange(path, "New sensitive system file appeared", content, contentKnown); emit {
				findings = append(findings, f)
			}
		case !sensitiveFileStateChanged(prevState, curState):
			// Unknown evidence and equivalent regular-file rewrites do not
			// establish a change.
		case sensitiveLiveReportMatches(liveReported[path], curState):
			// The live hook already delivered a finding for this exact state.
		default:
			summary := "Content changed on sensitive system file"
			if prevState.PathIdentity != "" && curState.PathIdentity != "" && prevState.PathIdentity != curState.PathIdentity {
				summary = "Path identity changed on sensitive system file"
			}
			if f, emit := evaluateSensitiveWatchsetChange(path, summary, content, contentKnown); emit {
				findings = append(findings, f)
			}
		}
	}
	return findings
}

func sensitiveFileStateChanged(prev, cur SensitiveFileState) bool {
	contentChanged := prev.ContentDigest != "" && cur.ContentDigest != "" && prev.ContentDigest != cur.ContentDigest
	pathChanged := prev.PathIdentity != "" && cur.PathIdentity != "" && prev.PathIdentity != cur.PathIdentity
	return contentChanged || pathChanged
}

func sensitiveLiveReportMatches(reported, cur SensitiveFileState) bool {
	return reported.ContentDigest != "" && reported.PathIdentity != "" && reported == cur
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
		// A content change CSM itself made (e.g. installing a wp-cron) updates
		// the stored baseline above but raises no finding.
		if isExpectedSelfWrite(path, data) {
			continue
		}
		if suppressedAsManagedWPCron(path, data) {
			continue
		}
		kind := classifySensitive(path)
		var contentForScore []byte
		if kind == "cron" {
			contentForScore = data
		}
		hashChange := alert.Finding{
			Severity:  alert.High,
			Check:     "sensitive_file_modified",
			Message:   fmt.Sprintf("Periodic check: content hash changed for %s", path),
			Details:   fmt.Sprintf("Previous: %s, Current: %s", prev, hashHex),
			FilePath:  path,
			Timestamp: time.Now(),
		}
		findings = append(findings, rescoreSensitive(hashChange, kind, contentForScore, 0, time.Now()))
	}
	if !baselineComplete {
		store.SetRaw(sensitiveFileBaselineKey, "1")
	}
	return findings
}
