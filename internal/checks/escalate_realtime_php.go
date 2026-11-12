package checks

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/contenttype"
)

// realtimePHPChecks are the realtime PHP content checks whose files get the
// scheduled analysis when realtime reports them.
var realtimePHPChecks = map[string]bool{
	"obfuscated_php_realtime":   true,
	"webshell_content_realtime": true,
	"php_dropper_realtime":      true,
}

// EscalateRealtimePHP runs the scheduled content analysis on the files behind
// Critical realtime PHP findings and returns the findings it rates Critical.
// Realtime reads a small window and only alerts on what it cannot confirm; the
// scheduled verdict is the one the scheduled response already acts on, so it
// can act now instead of when a scan next reaches the file.
func EscalateRealtimePHP(cfg *config.Config, findings []alert.Finding) []alert.Finding {
	if cfg == nil || !cfg.AutoResponse.Enabled || !cfg.AutoResponse.QuarantineFiles || cfg.ObserveMode() {
		return nil
	}
	seen := make(map[string]bool)
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
		if finding, ok := scheduledPHPFinding(path); ok {
			out = append(out, finding)
		}
	}
	return out
}

// scheduledPHPFinding analyses path as the scheduled content scan does. The
// open neither follows a link nor waits on a FIFO: the alert dispatcher calls
// it, and an attacker can swap either in at the reported path.
func scheduledPHPFinding(path string) (alert.Finding, bool) {
	if !contenttype.IsPHPSourceName(strings.ToLower(filepath.Base(path))) {
		return alert.Finding{}, false
	}
	// #nosec G304 -- path is a realtime finding's file under a watched root.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
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
	if !result.readOK || result.severity != alert.Critical {
		return alert.Finding{}, false
	}
	return phpContentFinding(path, result, info, digest), true
}
