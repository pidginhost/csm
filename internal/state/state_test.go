package state

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestSetLatestFindingsKeepsDistinctDetailsVariants(t *testing.T) {
	store := &Store{path: t.TempDir()}
	findings := []alert.Finding{
		{Check: "test", Message: "same", Details: "one"},
		{Check: "test", Message: "same", Details: "two"},
	}

	store.SetLatestFindings(findings)
	got := store.LatestFindings()
	if len(got) != 2 {
		t.Fatalf("expected 2 distinct findings, got %d", len(got))
	}
}

func TestIsSuppressedMatchesExtractedMessagePath(t *testing.T) {
	store := &Store{path: t.TempDir()}
	finding := alert.Finding{
		Check:   "malware",
		Message: "Suspicious file found: /home/user/public_html/bad.php",
	}
	rules := []SuppressionRule{{
		Check:       "malware",
		PathPattern: "/home/user/public_html/*",
	}}

	if !store.IsSuppressed(finding, rules) {
		t.Fatal("expected suppression to match extracted path")
	}
}
