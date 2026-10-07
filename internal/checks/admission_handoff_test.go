package checks

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/metrics"
)

// handoffSample reads one sample of the handoff histogram as a scraper sees
// it; absent reads as zero.
func handoffSample(t *testing.T, name string) float64 {
	t.Helper()
	var buf bytes.Buffer
	if err := metrics.WriteOpenMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(buf.String(), "\n") {
		if v, ok := strings.CutPrefix(line, name+" "); ok {
			n, err := strconv.ParseFloat(v, 64)
			if err != nil {
				t.Fatalf("parse %q: %v", line, err)
			}
			return n
		}
	}
	return 0
}

// R11: every handoff a funnel makes to admission is timed, with a bucket at
// the 10 ms the comparison's p99 criterion reads; nothing is timed while
// admission is not wired.
func TestAdmissionHandoffsAreTimed(t *testing.T) {
	const count = "csm_admission_handoff_seconds_count"
	f := alert.Finding{Check: "ssh_brute", SourceIP: "203.0.113.9", Severity: alert.Critical}
	SetResponseAdmission(nil)
	before := handoffSample(t, count)
	respond(admission.KindBlockIP, f, f.SourceIP, 0)
	AnswerRoot(admission.KindBlockIP, admission.Evidence{}, admission.EntryIncident)
	respondNetblock()
	_ = AdmissionRoot(f, f.SourceIP)
	if got := handoffSample(t, count); got != before {
		t.Fatalf("unwired handoffs were timed: %v, want %v", got, before)
	}
	a := withAdmission(t)
	beforeBucket := handoffSample(t, `csm_admission_handoff_seconds_bucket{le="0.01"}`)
	respond(admission.KindBlockIP, f, f.SourceIP, 0)
	AnswerRoot(admission.KindBlockIP, admission.Evidence{}, admission.EntryIncident)
	respondNetblock()
	for range 20 {
		_ = AdmissionRoot(f, f.SourceIP)
		_, _ = PrepareAdmissionRoot(f, f.SourceIP)
	}
	if got := handoffSample(t, count); got != before+3 {
		t.Fatalf("preparation added handoff samples: %v, want %v", got, before+3)
	}
	a.refuse = true
	_, refused := PrepareAdmissionRoot(f, f.SourceIP)
	AnswerPreparedRoot(admission.KindBlockIP, admission.Evidence{}, admission.EntryCentral, f, refused, 0)
	if got := handoffSample(t, count); got != before+4 {
		t.Fatalf("timed handoffs = %v, want %v", got, before+4)
	}
	if got := handoffSample(t, `csm_admission_handoff_seconds_bucket{le="0.01"}`); got-beforeBucket != 4 {
		t.Fatalf("10 ms bucket = %v", got)
	}
}
