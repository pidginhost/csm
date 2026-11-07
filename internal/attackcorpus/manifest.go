// Package attackcorpus loads the attack replay corpus: malicious samples and
// near-miss controls, each with what every detection path must report for it.
//
// Sample content stays base64-encoded at rest and is decoded in memory only,
// because endpoint antivirus deletes decoded web shells from a checkout.
package attackcorpus

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/safepath"
)

// Category groups samples by attack type.
type Category string

const (
	Webshell          Category = "webshell"
	Dropper           Category = "dropper"
	MaliciousPlugin   Category = "malicious_plugin"
	CredentialStealer Category = "credential_stealer" // #nosec G101 -- category name, not a credential.
	InjectedJS        Category = "injected_js"
	PhishingKit       Category = "phishing_kit"
	SpamScript        Category = "spam_script"
	Persistence       Category = "persistence"
	Binary            Category = "binary"
	Archive           Category = "archive"
)

// Categories lists every category; each needs a malicious sample and a control.
var Categories = []Category{
	Webshell, Dropper, MaliciousPlugin, CredentialStealer, InjectedJS,
	PhishingKit, SpamScript, Persistence, Binary, Archive,
}

// Path is a detection path a sample is replayed through.
type Path string

const (
	Realtime Path = "realtime"
	Tier     Path = "tier"
	FullScan Path = "fullscan"
)

// Paths lists every detection path; a manifest states its expectation for each.
var Paths = []Path{Realtime, Tier, FullScan}

// Remediation is what a path leaves on disk for one planted file.
type Remediation string

const (
	Quarantined Remediation = "quarantined"
	Cleaned     Remediation = "cleaned"
	Untouched   Remediation = "untouched"
	// Removed is only ever observed, never a valid expectation in a manifest.
	Removed Remediation = "removed"
)

// File is one planted file. Exactly one of B64 or Selftest is set.
type File struct {
	// Path is relative to the account home, or "@crontab" for the account's
	// crontab in the cron spool.
	Path string `json:"path"`
	// B64 names a base64 file beside the manifest.
	B64 string `json:"b64,omitempty"`
	// Selftest names a sample in the self-test bundle.
	Selftest string `json:"selftest,omitempty"`
	// Mode is permission bits only. JSON has no octal, so 0644 is written 420.
	Mode uint32 `json:"mode,omitempty"`
}

// ExpectedFinding is a finding a path must report.
type ExpectedFinding struct {
	Check string `json:"check"`
	File  string `json:"file"`
	// MinSeverity is warning, high or critical, in any case.
	MinSeverity string `json:"min_severity"`
}

// PathExpect is what one path must do with a sample. Files missing from
// Remediation are expected untouched.
type PathExpect struct {
	Findings      []ExpectedFinding      `json:"findings"`
	Gap           string                 `json:"gap"`
	Remediation   map[string]Remediation `json:"remediation"`
	CleanedSHA256 map[string]string      `json:"cleaned_sha256"`
}

// Sample is one corpus entry, read from <category>/<name>/sample.json.
type Sample struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	// Kind is malicious or control.
	Kind string `json:"kind"`
	// Source is synthetic, fixture or real.
	Source      string              `json:"source"`
	Description string              `json:"description"`
	Provenance  string              `json:"provenance"`
	Files       []File              `json:"files"`
	Expect      map[Path]PathExpect `json:"expect"`
	// Dir is the sample directory the manifest was read from.
	Dir string `json:"-"`
	// Half is public or private.
	Half string `json:"-"`

	// Keep later reads anchored to the original corpus even if Dir or cwd changes.
	corpusDir   string
	relativeDir string
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// severityLevel maps a manifest severity to the alert level it names.
func severityLevel(s string) (alert.Severity, bool) {
	switch strings.ToLower(s) {
	case "warning":
		return alert.Warning, true
	case "high":
		return alert.High, true
	case "critical":
		return alert.Critical, true
	}
	return 0, false
}

// checkPath accepts a clean path inside the account, or the one reserved name.
func checkPath(p string) error {
	if p == "@crontab" {
		return nil
	}
	if !filepath.IsLocal(p) || filepath.Clean(p) != p || p == "." || strings.HasPrefix(p, "@") || strings.ContainsRune(p, '\x00') {
		return fmt.Errorf("unsafe path %q", p)
	}
	return nil
}

func (s Sample) validate(dir *safepath.Dir) error {
	switch {
	case !slices.Contains(Categories, Category(s.Category)):
		return fmt.Errorf("unknown category %q", s.Category)
	case s.Kind != "malicious" && s.Kind != "control":
		return fmt.Errorf("unknown kind %q", s.Kind)
	case s.Source != "synthetic" && s.Source != "fixture" && s.Source != "real":
		return fmt.Errorf("unknown source %q", s.Source)
	case len(s.Files) == 0:
		return errors.New("no files")
	}

	files := make(map[string]bool, len(s.Files))
	for _, f := range s.Files {
		if err := checkPath(f.Path); err != nil {
			return err
		}
		if files[f.Path] {
			return fmt.Errorf("duplicate path %q", f.Path)
		}
		files[f.Path] = true
		if (f.B64 == "") == (f.Selftest == "") {
			return fmt.Errorf("file %q: set exactly one of b64 or selftest", f.Path)
		}
		if f.B64 != "" && (filepath.Base(f.B64) != f.B64 || !filepath.IsLocal(f.B64)) {
			return fmt.Errorf("file %q: b64 %q must be a file name beside the manifest", f.Path, f.B64)
		}
		// fixturecheck scans sample data decoded; a .b64 name keeps the two in step.
		if f.B64 != "" && !strings.HasSuffix(f.B64, ".b64") {
			return fmt.Errorf("file %q: b64 %q must end in \".b64\"", f.Path, f.B64)
		}
		if f.Mode&^0o777 != 0 {
			return fmt.Errorf("file %q: mode %#o has bits beyond the permission bits", f.Path, f.Mode)
		}
		if _, err := content(dir, f); err != nil {
			return fmt.Errorf("file %q: %w", f.Path, err)
		}
	}
	for file := range files {
		for parent := filepath.Dir(file); parent != "."; parent = filepath.Dir(parent) {
			if files[parent] {
				return fmt.Errorf("conflicting paths %q and %q", parent, file)
			}
		}
	}

	for p := range s.Expect {
		if !slices.Contains(Paths, p) {
			return fmt.Errorf("expect: unknown path %q", p)
		}
	}
	for _, p := range Paths {
		e, ok := s.Expect[p]
		if !ok {
			return fmt.Errorf("missing expect for %s", p)
		}
		if err := s.validateExpect(e, files); err != nil {
			return fmt.Errorf("expect %s: %w", p, err)
		}
	}
	return nil
}

func (s Sample) validateExpect(e PathExpect, files map[string]bool) error {
	switch {
	case e.Gap != "" && len(e.Findings) > 0:
		return errors.New("gap and findings are exclusive")
	case s.Kind == "control" && (e.Gap != "" || len(e.Findings) > 0):
		return errors.New("a control expects no gap or findings")
	case s.Kind == "malicious" && strings.TrimSpace(e.Gap) == "" && len(e.Findings) == 0:
		return errors.New("a malicious sample needs findings or a gap")
	}
	for _, f := range e.Findings {
		if f.Check == "" {
			return fmt.Errorf("finding for %q has no check", f.File)
		}
		if !files[f.File] {
			return fmt.Errorf("finding file %q is not in files", f.File)
		}
		if _, ok := severityLevel(f.MinSeverity); !ok {
			return fmt.Errorf("finding %s: unknown severity %q", f.Check, f.MinSeverity)
		}
	}
	for file, r := range e.Remediation {
		if !files[file] {
			return fmt.Errorf("remediation file %q is not in files", file)
		}
		if r != Quarantined && r != Cleaned && r != Untouched {
			return fmt.Errorf("file %q: remediation %q is not allowed", file, r)
		}
		if s.Kind == "control" && r != Untouched {
			return fmt.Errorf("a control leaves every file untouched, %q is %s", file, r)
		}
		if r == Cleaned && !sha256Hex.MatchString(e.CleanedSHA256[file]) {
			return fmt.Errorf("file %q is cleaned but has no valid cleaned_sha256", file)
		}
	}
	for file := range e.CleanedSHA256 {
		if e.Remediation[file] != Cleaned {
			return fmt.Errorf("cleaned_sha256 for %q, which is not cleaned", file)
		}
	}
	return nil
}
