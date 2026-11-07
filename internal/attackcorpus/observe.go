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
	"github.com/pidginhost/csm/internal/safepath"
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

// MarshalJSON writes the severity by name: alert.Severity has no JSON form of
// its own and would appear in reports as 0, 1 or 2.
func (o Observed) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Check    string `json:"check"`
		Severity string `json:"severity"`
		File     string `json:"file"`
	}{o.Check, o.Severity.String(), o.File})
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
// directory's and retains the original bytes, and removed otherwise. A file
// with changed bytes is cleaned, with the SHA-256 of what is left. Missing
// baselines or damaged quarantine entries are errors. quarantineDir must be
// the sample's own, so every entry in it is new.
func ObserveRemediation(planted map[string]string, original map[string][]byte, quarantineDir string) (map[string]Remediation, map[string]string, error) {
	quarantine, err := safepath.OpenDir(quarantineDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, err
	}
	if quarantine != nil {
		defer func() { _ = quarantine.Close() }()
	}
	moved, err := quarantinedPaths(quarantine)
	if err != nil {
		return nil, nil, err
	}
	remediation := make(map[string]Remediation, len(planted))
	sums := map[string]string{}
	for p, abs := range planted {
		before := original[p]
		if len(before) == 0 {
			return nil, nil, fmt.Errorf("%s: missing original content", p)
		}
		// #nosec G304 -- abs is a file Plant wrote under the test's temp tree.
		data, err := os.ReadFile(abs)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			remediation[p] = Removed
			for _, entry := range moved {
				rel, relErr := filepath.Rel(entry.original, abs)
				if relErr != nil || (rel != "." && !filepath.IsLocal(rel)) {
					continue
				}
				retained := filepath.Join(entry.archived, rel)
				dir, openErr := quarantine.Walk(filepath.Dir(retained))
				if openErr != nil {
					return nil, nil, fmt.Errorf("%s: open retained quarantine: %w", p, openErr)
				}
				retainedData, readErr := readRegularFile(dir, filepath.Base(retained))
				_ = dir.Close()
				if readErr != nil {
					return nil, nil, fmt.Errorf("%s: read retained quarantine: %w", p, readErr)
				}
				if !bytes.Equal(retainedData, before) {
					return nil, nil, fmt.Errorf("%s: quarantined content differs from original", p)
				}
				remediation[p] = Quarantined
			}
		case err != nil:
			return nil, nil, fmt.Errorf("%s: %w", p, err)
		case bytes.Equal(data, before):
			remediation[p] = Untouched
		default:
			remediation[p] = Cleaned
			sum := sha256.Sum256(data)
			sums[p] = hex.EncodeToString(sum[:])
		}
	}
	return remediation, sums, nil
}

type quarantineEntry struct{ original, archived string }

// quarantinedPaths reads the original path from each quarantine entry's .meta
// sidecar. Only top-level entries count: pre_clean below it holds the backups
// a cleaning takes, not quarantined files.
func quarantinedPaths(dir *safepath.Dir) ([]quarantineEntry, error) {
	if dir == nil {
		return nil, nil
	}
	entries, err := dir.ReadDir()
	if err != nil {
		return nil, err
	}
	var paths []quarantineEntry
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".meta") {
			continue
		}
		data, err := readRegularFile(dir, e.Name())
		if err != nil {
			return nil, err
		}
		var meta struct {
			OriginalPath string `json:"original_path"`
		}
		if err := json.Unmarshal(data, &meta); err != nil {
			return nil, fmt.Errorf("quarantine sidecar %s: invalid metadata JSON", e.Name())
		}
		if !filepath.IsAbs(meta.OriginalPath) || filepath.Clean(meta.OriginalPath) != meta.OriginalPath {
			return nil, fmt.Errorf("quarantine sidecar %s has no absolute clean original path", e.Name())
		}
		paths = append(paths, quarantineEntry{original: meta.OriginalPath, archived: strings.TrimSuffix(e.Name(), ".meta")})
	}
	return paths, nil
}
