package checks

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/contenttype"
	"github.com/pidginhost/csm/internal/safepath"
)

// realtimePHPChecks are the realtime PHP content checks whose files get the
// scheduled analysis when realtime reports them.
var realtimePHPChecks = map[string]bool{
	"obfuscated_php_realtime":   true,
	"webshell_content_realtime": true,
	"php_dropper_realtime":      true,
}

// RealtimePHPEscalationCandidates selects files not already covered by a file
// response in this batch. Another detector may have evaluated the same file,
// including a refused attempt, so inspect the whole batch first.
func RealtimePHPEscalationCandidates(cfg *config.Config, findings []alert.Finding) []alert.Finding {
	if cfg == nil || !cfg.AutoResponse.Enabled || !cfg.AutoResponse.QuarantineFiles || cfg.ObserveMode() {
		return nil
	}
	seen := make(map[string]bool)
	for _, f := range findings {
		if f.FilePath != "" && (f.AutoFileResponseEvaluated ||
			(autoQuarantineChecks[f.Check] && f.Severity == alert.Critical)) {
			seen[filepath.Clean(f.FilePath)] = true
		}
	}
	var out []alert.Finding
	for _, f := range findings {
		if !realtimePHPChecks[f.Check] || f.Severity != alert.Critical || f.FilePath == "" {
			continue
		}
		path := filepath.Clean(f.FilePath)
		if seen[path] {
			continue
		}
		seen[path] = true
		f.FilePath = path
		out = append(out, f)
	}
	return out
}

// EscalateRealtimePHP runs scheduled analysis outside the alert dispatcher.
// Results must re-enter normal dispatch for state and suppression checks.
func EscalateRealtimePHP(cfg *config.Config, findings []alert.Finding) []alert.Finding {
	var out []alert.Finding
	for _, f := range RealtimePHPEscalationCandidates(cfg, findings) {
		if finding, ok := scheduledPHPFinding(f.FilePath); ok {
			finding.TenantID = f.TenantID
			finding.Domain = f.Domain
			finding.ProcessInfo = f.ProcessInfo
			finding.PID = f.PID
			out = append(out, finding)
		}
	}
	return out
}

// scheduledPHPFinding analyses path as the scheduled content scan does. The
// open rejects links in every component and does not wait on a FIFO.
// Regular-file I/O can still stall, so callers must run outside dispatch.
func scheduledPHPFinding(path string) (alert.Finding, bool) {
	if !contenttype.IsPHPSourceName(strings.ToLower(filepath.Base(path))) {
		return alert.Finding{}, false
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return alert.Finding{}, false
	}
	target, err := safepath.OpenTarget("/", strings.TrimPrefix(path, "/"), false)
	if err != nil {
		return alert.Finding{}, false
	}
	defer target.Close()
	f, err := target.Parent.OpenFile(target.Name, os.O_RDONLY, 0)
	if err != nil {
		return alert.Finding{}, false
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return alert.Finding{}, false
	}
	var result phpAnalysisResult
	digest := ""
	if info.Size() <= contentFingerprintMaxBytes {
		data, readErr := io.ReadAll(io.LimitReader(f, contentFingerprintMaxBytes+1))
		if readErr != nil || int64(len(data)) != info.Size() {
			return alert.Finding{}, false
		}
		result = analyzePHPContentReaderAt(path, bytes.NewReader(data), int64(len(data)))
		digest = fmt.Sprintf("%x", sha256.Sum256(data))
	} else {
		result = analyzePHPContentReaderAt(path, f, info.Size())
	}
	after, err := f.Stat()
	if err != nil || !SameFileVersion(info, after) || target.Check() != nil {
		return alert.Finding{}, false
	}
	current, err := target.Parent.Stat(target.Name)
	if err != nil || !SameFileVersion(info, current) {
		return alert.Finding{}, false
	}
	if !result.readOK || result.severity != alert.Critical {
		return alert.Finding{}, false
	}
	finding := phpContentFinding(path, result, info, digest)
	finding.FileResponseIdentity = fileResponseIdentity(info)
	if finding.FileResponseIdentity == "" {
		return alert.Finding{}, false
	}
	return finding, true
}

// The token includes ctime so restoring size and mtime cannot disguise a
// same-inode rewrite. It survives pending replay without publishing inode data.
func fileResponseIdentity(info os.FileInfo) string {
	identity, ok := selfWriteIdentityFromFileInfo(info)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d:%d:%d:%d:%d:%d:%d", identity.Device, identity.Inode,
		identity.ChangeSec, identity.ChangeNsec, info.Size(), info.ModTime().UnixNano(), info.Mode())
}
