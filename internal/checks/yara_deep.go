package checks

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/yara"
)

var activeYARABackend = yara.Active
var yaraAvailable = yara.Available

func CheckYARADeep(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	backend := activeYARABackend()
	if backend == nil || backend.RuleCount() == 0 {
		markCheckIncomplete(ctx, "yara_deep")
		if yaraAvailable() {
			return []alert.Finding{{
				Severity: alert.High,
				Check:    "yara_scan_incomplete",
				Message:  "YARA deep scan could not start because no compiled rules are available",
			}}
		}
		return nil
	}
	maxBytes := int64(FullScanMaxFileBytes(cfg))
	var findings []alert.Finding
	var incomplete int
	var firstIncomplete string

	var scanDir func(string)
	scanDir = func(dir string) {
		if ctx.Err() != nil {
			return
		}
		entries, err := osFS.ReadDir(dir)
		if err != nil {
			incomplete++
			if firstIncomplete == "" {
				firstIncomplete = fmt.Sprintf("reading %s: %v", dir, err)
			}
			return
		}
		for _, entry := range entries {
			if ctx.Err() != nil {
				return
			}
			path := filepath.Join(dir, entry.Name())
			info, err := osFS.Lstat(path)
			if err != nil {
				incomplete++
				if firstIncomplete == "" {
					firstIncomplete = fmt.Sprintf("inspecting %s: %v", path, err)
				}
				continue
			}
			if info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			if info.IsDir() {
				scanDir(path)
				continue
			}
			if !info.Mode().IsRegular() || info.Size() == 0 {
				continue
			}
			if info.Size() > maxBytes {
				incomplete++
				if firstIncomplete == "" {
					firstIncomplete = fmt.Sprintf("%s exceeds the %d-byte scan limit", path, maxBytes)
				}
				continue
			}

			file, err := osFS.Open(path)
			if err != nil {
				incomplete++
				if firstIncomplete == "" {
					firstIncomplete = fmt.Sprintf("opening %s: %v", path, err)
				}
				continue
			}
			openedInfo, statErr := file.Stat()
			if statErr != nil || !openedInfo.Mode().IsRegular() || openedInfo.Size() > maxBytes {
				_ = file.Close()
				incomplete++
				if firstIncomplete == "" {
					firstIncomplete = fmt.Sprintf("%s changed while it was being opened", path)
				}
				continue
			}
			data, readErr := io.ReadAll(io.LimitReader(file, maxBytes+1))
			closeErr := file.Close()
			if readErr != nil || closeErr != nil || int64(len(data)) > maxBytes {
				incomplete++
				if firstIncomplete == "" {
					firstIncomplete = fmt.Sprintf("reading %s failed or exceeded the scan limit", path)
				}
				continue
			}
			matches, scanErr := yara.ScanBytesChecked(backend, data)
			if scanErr != nil {
				incomplete++
				if firstIncomplete == "" {
					firstIncomplete = fmt.Sprintf("scanning %s: %v", path, scanErr)
				}
				continue
			}
			fingerprint := sha256.Sum256(data)
			for _, match := range matches {
				finding := alert.Finding{
					Severity:      yaraMatchSeverity(match.Meta["severity"]),
					Check:         "yara_match_scheduled",
					Message:       fmt.Sprintf("YARA rule match [%s]: %s", match.RuleName, path),
					Details:       fmt.Sprintf("Scheduled deep scan matched YARA rule %s", match.RuleName),
					FilePath:      path,
					ContentSHA256: fmt.Sprintf("%x", fingerprint),
					DetectLogic:   ContentDetectionVersion(),
				}
				findings = append(findings, finding)
			}
		}
	}

	for _, root := range ResolveWebRoots(cfg) {
		scanDir(root)
	}
	if ctx.Err() != nil {
		return nil
	}
	if incomplete > 0 {
		markCheckIncomplete(ctx, "yara_deep")
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "yara_scan_incomplete",
			Message:  fmt.Sprintf("YARA deep scan could not inspect %d file or directory entries", incomplete),
			Details:  firstIncomplete,
		})
	}
	return findings
}

func yaraMatchSeverity(value string) alert.Severity {
	switch strings.ToLower(value) {
	case "warning", "low", "medium":
		return alert.Warning
	case "high":
		return alert.High
	default:
		return alert.Critical
	}
}
