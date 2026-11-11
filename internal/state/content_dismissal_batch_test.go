package state

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// Once a batch proves new content, its observations of the dismissed,
// unknown or carried content must not reach deduplication ahead of it.
func TestReconcileKeepsOnlyNewContentOfRevokedKey(t *testing.T) {
	unknown := contentFinding("yara_match_scheduled", "")
	carried := contentFinding("yara_match_scheduled", shaB)
	carried.ScanCarryForward = true
	b := contentFinding("yara_match_scheduled", shaB)
	other := contentFinding("yara_match_scheduled", shaA)
	other.Message = "YARA rule match [webshell_generic]: /home/a/public_html/y.php"
	other.FilePath = "/home/a/public_html/y.php"
	for _, tc := range []struct {
		name  string
		batch []alert.Finding
	}{
		{name: "dismissed first", batch: []alert.Finding{contentFinding("yara_match_scheduled", shaA), b, other}},
		{name: "dismissed last", batch: []alert.Finding{b, contentFinding("yara_match_scheduled", shaA), other}},
		{name: "unknown first", batch: []alert.Finding{unknown, b, other}},
		{name: "carried first", batch: []alert.Finding{carried, b, other}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := openTestStore(t)
			s.SetBaseline([]alert.Finding{contentFinding("yara_match_scheduled", shaA), other})

			got := s.ReconcileDismissedContent(tc.batch)

			if len(got) != 2 || got[0].Key() != b.Key() || got[0].ContentSHA256 != shaB || got[0].ScanCarryForward ||
				got[1].Key() != other.Key() {
				t.Fatalf("batch = %+v, want the new content and the unrelated finding", got)
			}
		})
	}
}

func TestReconcileReturnsBatchWithoutRevocation(t *testing.T) {
	s := openTestStore(t)
	a := contentFinding("yara_match_scheduled", shaA)
	s.SetBaseline([]alert.Finding{a})
	unknown := contentFinding("yara_match_scheduled", "")
	batch := []alert.Finding{a, unknown}

	if got := s.ReconcileDismissedContent(batch); len(got) != 2 {
		t.Fatalf("batch = %+v, want it unchanged", got)
	}
}

func TestReconcileAdoptsAndRevokesLegacyContentInOneBatch(t *testing.T) {
	s := openTestStore(t)
	unknown := contentFinding("yara_match_scheduled", "")
	s.SetBaseline([]alert.Finding{unknown})
	a, b := contentFinding(unknown.Check, shaA), contentFinding(unknown.Check, shaB)
	carried := b
	carried.ScanCarryForward = true

	got := s.ReconcileDismissedContent([]alert.Finding{unknown, carried, a, b, a})

	if len(got) != 1 || got[0].ContentSHA256 != shaB || got[0].ScanCarryForward {
		t.Fatalf("batch = %+v, want the fresh content that ended the adopted dismissal", got)
	}
	if _, ok := s.EntryForKey(b.Key()); ok {
		t.Fatal("legacy dismissal survived differing content in the same batch")
	}
	if fresh := s.FilterNew(alert.Deduplicate(got)); len(fresh) != 1 || fresh[0].ContentSHA256 != shaB {
		t.Fatalf("new findings = %+v, want the changed content", fresh)
	}
}

func TestReconcileLogsEndedDismissal(t *testing.T) {
	s := openTestStore(t)
	a, b := contentFinding("yara_match_scheduled", shaA), contentFinding("yara_match_scheduled", shaB)
	s.SetBaseline([]alert.Finding{a})

	out := captureStderr(t, func() { s.ReconcileDismissedContent([]alert.Finding{a}) })
	if out != "" {
		t.Fatalf("unchanged content logged %q", out)
	}
	out = captureStderr(t, func() { s.ReconcileDismissedContent([]alert.Finding{b}) })
	if !strings.Contains(out, "content changed") || !strings.Contains(out, a.FilePath) {
		t.Fatalf("log = %q, want the ended dismissal and its file", out)
	}
}

func TestReconcileLogKeepsUntrustedKeyOnOneLine(t *testing.T) {
	s := openTestStore(t)
	a := contentFinding("yara_match_scheduled", shaA)
	a.FilePath = "/home/a/public_html/line\nbreak\x1b[2J.php"
	a.Message = "YARA rule match [webshell_generic]: " + a.FilePath
	b := a
	b.ContentSHA256 = shaB
	s.SetBaseline([]alert.Finding{a})

	out := captureStderr(t, func() { s.ReconcileDismissedContent([]alert.Finding{b}) })

	if !strings.Contains(out, "content changed") || !strings.Contains(out, `line\nbreak\x1b[2J.php`) {
		t.Errorf("log = %q, want the ended dismissal with escaped file name", out)
	}
	if strings.Count(out, "\n") != 1 || strings.ContainsRune(out, '\x1b') {
		t.Errorf("log = %q, want one line without terminal control characters", out)
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	os.Stderr = w
	defer func() { os.Stderr = old }()
	fn()
	if closeErr := w.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}
