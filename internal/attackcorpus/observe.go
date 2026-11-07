package attackcorpus

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
)

// Observed is one finding a path reported, as the judge sees it.
type Observed struct {
	Check    string         `json:"check"`
	Severity alert.Severity `json:"severity"`
	// File is the sample path the finding names, "" when unattributed.
	File string `json:"file"`
	// Text is the finding's message and details. Details can quote sample
	// content, so Text is for the judge only and never reaches a report.
	Text string `json:"-"`
}

// ObservedFrom converts a finding, so every driver builds Text the same way.
func ObservedFrom(f alert.Finding, file string) Observed {
	return Observed{Check: f.Check, Severity: f.Severity, File: file, Text: f.Message + "\n" + f.Details}
}

// Outcome is what a driver saw when it ran one sample through one path.
type Outcome struct {
	Findings      []Observed
	Remediation   map[string]Remediation
	CleanedSHA256 map[string]string
	// NotAdmitted lists sample paths the realtime admission filter dropped.
	NotAdmitted     []string
	NetworkAttempts int64
	Err             error
}

// ObserveRemediation reports what happened to each planted file. A missing
// file is quarantined when a quarantine entry records its path or a parent
// directory's, and removed otherwise. A file with changed bytes is cleaned,
// with the SHA-256 of what is left. quarantineDir must be the sample's own, so
// every entry in it is new.
func ObserveRemediation(planted map[string]string, original map[string][]byte, quarantineDir string) (map[string]Remediation, map[string]string, error) {
	moved, err := quarantinedPaths(quarantineDir)
	if err != nil {
		return nil, nil, err
	}
	remediation := make(map[string]Remediation, len(planted))
	sums := map[string]string{}
	for p, abs := range planted {
		// #nosec G304 -- abs is a file Plant wrote under the test's temp tree.
		data, err := os.ReadFile(abs)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			remediation[p] = Removed
			for _, orig := range moved {
				if abs == orig || strings.HasPrefix(abs, orig+string(filepath.Separator)) {
					remediation[p] = Quarantined
				}
			}
		case err != nil:
			return nil, nil, fmt.Errorf("%s: %w", p, err)
		case bytes.Equal(data, original[p]):
			remediation[p] = Untouched
		default:
			remediation[p] = Cleaned
			sum := sha256.Sum256(data)
			sums[p] = hex.EncodeToString(sum[:])
		}
	}
	return remediation, sums, nil
}

// quarantinedPaths reads the original path from each quarantine entry's .meta
// sidecar. Only top-level entries count: pre_clean below it holds the backups
// a cleaning takes, not quarantined files.
func quarantinedPaths(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".meta") {
			continue
		}
		// #nosec G304 -- a sidecar inside the sample's own quarantine dir.
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var meta struct {
			OriginalPath string `json:"original_path"`
		}
		if err := json.Unmarshal(data, &meta); err != nil {
			return nil, fmt.Errorf("quarantine sidecar %s: %w", e.Name(), err)
		}
		// An empty path would prefix-match every planted file.
		if meta.OriginalPath == "" {
			return nil, fmt.Errorf("quarantine sidecar %s has no original path", e.Name())
		}
		paths = append(paths, meta.OriginalPath)
	}
	return paths, nil
}
