package attackcorpus

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
)

// Result is the verdict for one sample on one path. It goes into the report,
// so it holds names, paths and verdicts, never sample content.
type Result struct {
	Sample          string                 `json:"sample"`
	Category        string                 `json:"category"`
	Kind            string                 `json:"kind"`
	Half            string                 `json:"half"`
	Path            Path                   `json:"path"`
	Pass            bool                   `json:"pass"`
	Failures        []string               `json:"failures,omitempty"`
	Findings        []Observed             `json:"findings,omitempty"`
	Remediation     map[string]Remediation `json:"remediation"`
	Gap             string                 `json:"gap,omitempty"`
	NotAdmitted     []string               `json:"not_admitted,omitempty"`
	NetworkAttempts int64                  `json:"network_attempts"`
}

// Judge compares what a path did with a sample against the sample's manifest.
// Each failure starts with its kind: "missed:", "severity:", "false
// positive:", "remediation:", "gap closed:" or "error:". An outcome with an
// error is not judged further. Extra findings on a malicious sample are kept
// in Findings and never fail it. For malicious samples, findings on a file the
// admission filter dropped are discarded, so that file counts as not detected.
// A control's findings are always retained: admission cannot excuse a false positive.
//
// An unattributed control finding is a false positive when its text names a
// sample path, and an attribution error otherwise. On a path with a gap, an
// unattributed finding whose text names an admitted sample path closes the
// gap. @crontab is not matched in text because its real name is the account,
// which Judge is not given. Drivers must attribute crontab findings and exclude
// proven unrelated host findings before returning an outcome.
//
// Findings are sorted by file, check, severity and text, so reports and
// failures do not depend on the order scanners report in.
func Judge(s Sample, p Path, o Outcome) Result {
	e := s.Expect[p]
	r := Result{
		Sample: s.Name, Category: s.Category, Kind: s.Kind, Half: s.Half, Path: p,
		Remediation: o.Remediation, Gap: e.Gap, NotAdmitted: o.NotAdmitted, NetworkAttempts: o.NetworkAttempts,
	}
	for _, f := range o.Findings {
		if s.Kind == "control" || !slices.Contains(o.NotAdmitted, f.File) {
			r.Findings = append(r.Findings, f)
		}
	}
	slices.SortFunc(r.Findings, func(a, b Observed) int {
		return cmp.Or(cmp.Compare(a.File, b.File), cmp.Compare(a.Check, b.Check), cmp.Compare(a.Severity, b.Severity), cmp.Compare(a.Text, b.Text))
	})
	r.Failures = failures(s, e, r.Findings, o)
	r.Pass = len(r.Failures) == 0
	return r
}

func failures(s Sample, e PathExpect, findings []Observed, o Outcome) []string {
	if o.Err != nil {
		// Parser and scanner errors can quote decoded content, just like findings.
		return []string{"error: driver did not complete"}
	}
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }

	for _, want := range e.Findings {
		best := alert.Severity(-1)
		for _, f := range findings {
			if f.Check == want.Check && f.File == want.File && f.Severity > best {
				best = f.Severity
			}
		}
		floor, _ := severityLevel(want.MinSeverity)
		switch {
		case best < 0:
			add("missed: %s on %s", want.Check, want.File)
		case best < floor:
			add("severity: %s on %s is %s, want %s or above", want.Check, want.File, best, floor)
		}
	}

	for _, f := range findings {
		named := -1
		if f.File == "" {
			named = slices.IndexFunc(s.Files, func(sf File) bool {
				return sf.Path != "@crontab" && strings.Contains(f.Text, sf.Path) &&
					(s.Kind == "control" || !slices.Contains(o.NotAdmitted, sf.Path))
			})
		}
		switch {
		case f.File == "" && s.Kind == "control" && named >= 0:
			add("false positive: %s names %s", f.Check, s.Files[named].Path)
		case f.File == "" && s.Kind == "control":
			add("error: unattributed finding %s on control", f.Check)
		case f.File == "" && e.Gap != "" && named >= 0:
			add("gap closed: %s names %s", f.Check, s.Files[named].Path)
		case f.File == "":
			// An unattributed extra finding on a malicious sample.
		case s.Kind == "control":
			add("false positive: %s on %s", f.Check, f.File)
		case e.Gap != "":
			add("gap closed: %s on %s", f.Check, f.File)
		}
	}

	for _, f := range s.Files {
		want, got := e.Remediation[f.Path], o.Remediation[f.Path]
		if want == "" {
			want = Untouched
		}
		switch {
		case got != want:
			add("remediation: %s is %s, want %s", f.Path, got, want)
		case want == Cleaned && o.CleanedSHA256[f.Path] != e.CleanedSHA256[f.Path]:
			add("remediation: %s cleaned to sha256 %s, want %s", f.Path, o.CleanedSHA256[f.Path], e.CleanedSHA256[f.Path])
		}
	}
	return out
}
