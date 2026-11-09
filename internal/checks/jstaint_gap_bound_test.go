package checks

import (
	"fmt"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/jstaint"
)

// The JS consumer records one gap per file it could not analyze. When the
// analyzer cannot run, that is every candidate script on the host, and
// retaining one path string per file for the length of a scan grows without
// limit. Past the bound the run keeps counting but reports its exact path set
// as incomplete, so the purge is suppressed instead of carrying forward an
// arbitrary prefix.
func TestJSTaintGapPathsAreBounded(t *testing.T) {
	status := jstaint.StatusResourceLimit.String()
	gaps := newJSTaintGapCollector()
	for i := 0; i < maxJSTaintGapPaths; i++ {
		gaps.record(fmt.Sprintf("/home/u/public_html/f%d.js", i), status)
	}
	// Seeing a retained path again still leaves the exact set authoritative.
	gaps.record("/home/u/public_html/f0.js", status)
	if gaps.pathsIncomplete() {
		t.Fatal("duplicate retained path falsely reported the exact set as incomplete")
	}
	gaps.record("/home/u/public_html/overflow.js", status)
	if !gaps.pathsIncomplete() {
		t.Fatal("hit the bound without reporting the path set as incomplete")
	}
	if len(gaps.paths) != maxJSTaintGapPaths {
		t.Fatalf("retained %d paths, want exactly %d", len(gaps.paths), maxJSTaintGapPaths)
	}
	if gaps.hasPath("/home/u/public_html/overflow.js") {
		t.Fatal("a path past the bound was retained")
	}
	finding := gaps.finding()
	if !strings.Contains(finding.Message, fmt.Sprint(maxJSTaintGapPaths+2)) {
		t.Fatalf("message = %q, want the full count", finding.Message)
	}
	if !strings.Contains(finding.Details, "retained for only the first") {
		t.Fatalf("details = %q, want the truncation stated", finding.Details)
	}
}
