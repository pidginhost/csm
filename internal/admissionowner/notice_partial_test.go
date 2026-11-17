package admissionowner

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
)

// A live partial-containment record alerts Critical and says that
// outbound-only traffic to the address still leaves.
func TestPartialContainmentNoticeFinding(t *testing.T) {
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	r := admission.NoticeRecord{Key: admission.PartialContainmentKey("c2_connection", admission.EffectAddress), Count: 1, First: now, Last: now}
	got := noticeFinding(r, now, true)
	if got.Severity != alert.Critical || got.Check != "auto_response_withheld" || !strings.Contains(got.Message, "partial containment") || !strings.Contains(got.Message, "outbound-only") {
		t.Fatalf("live finding = %+v", got)
	}
	if !strings.Contains(got.Details, "reason=unsupported_containment outcome=applied check=c2_connection") {
		t.Fatalf("details = %q", got.Details)
	}
	if preview := noticeFinding(r, now, false); preview.Severity != alert.Warning || !strings.HasPrefix(preview.Message, "Admission preview: ") || !strings.Contains(preview.Message, "partial containment") {
		t.Fatalf("preview finding = %+v", preview)
	}
}
