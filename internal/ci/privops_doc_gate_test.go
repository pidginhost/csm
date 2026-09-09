package ci

import (
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/privops"
)

const (
	matrixDocPath = "../../docs/src/capability-matrix.md"
	matrixBegin   = "<!-- BEGIN GENERATED MATRIX -->"
	matrixEnd     = "<!-- END GENERATED MATRIX -->"
)

// The published matrix has to be the inventory, not a prose copy of it that
// drifts one release later.
func TestCapabilityMatrixDocMatchesInventory(t *testing.T) {
	data, err := os.ReadFile(matrixDocPath)
	if err != nil {
		t.Fatalf("read %s: %v", matrixDocPath, err)
	}
	doc := string(data)

	start := strings.Index(doc, matrixBegin)
	end := strings.Index(doc, matrixEnd)
	if start < 0 || end < 0 || end < start {
		t.Fatalf("%s has no generated matrix block", matrixDocPath)
	}
	got := strings.TrimSpace(doc[start+len(matrixBegin) : end])
	want := strings.TrimSpace(privops.Markdown())
	if got != want {
		t.Errorf("%s is out of date; regenerate it with `go run ./cmd/csm privileges --markdown`", matrixDocPath)
	}
}
