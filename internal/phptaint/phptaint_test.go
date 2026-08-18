package phptaint

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestStatusStringsAreStable(t *testing.T) {
	want := map[Status]string{
		StatusNotCandidate:  "not_candidate",
		StatusAnalyzed:      "analyzed",
		StatusOversize:      "oversize",
		StatusParseError:    "parse_error",
		StatusPartialParse:  "partial_parse",
		StatusResourceLimit: "resource_limit",
		StatusCanceled:      "canceled",
		StatusPanic:         "panic",
	}
	for status, name := range want {
		if got := status.String(); got != name {
			t.Errorf("Status(%d).String() = %q, want %q", status, got, name)
		}
	}
}

func TestAnalyzeRejectsOversizeBeforeParsing(t *testing.T) {
	src := make([]byte, MaxSourceBytes+1)
	copy(src, "<?php eval(file_get_contents($u));")
	rep := Analyze(context.Background(), src)
	if rep.Status != StatusOversize {
		t.Fatalf("Status = %v, want StatusOversize", rep.Status)
	}
	if len(rep.Results) != 0 {
		t.Errorf("Results = %d, want 0 for a non-analyzed status", len(rep.Results))
	}
}

func TestAnalyzeHandlesCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep := Analyze(ctx, []byte("<?php eval($x);"))
	if rep.Status != StatusCanceled {
		t.Fatalf("Status = %v, want StatusCanceled", rep.Status)
	}
	if len(rep.Results) != 0 {
		t.Errorf("Results = %d, want 0 for a non-analyzed status", len(rep.Results))
	}
}

func TestRecoveredClearsEvidenceFromEveryIncompleteStatus(t *testing.T) {
	for _, status := range []Status{
		StatusNotCandidate, StatusOversize, StatusParseError, StatusPartialParse,
		StatusResourceLimit, StatusCanceled, StatusPanic, Status(255),
	} {
		rep := recovered(func() Report {
			return Report{
				Status:            status,
				Results:           []Result{{Source: "source", Sink: "eval"}},
				TotalResults:      1,
				PrecisionLoss:     []string{"dynamic-call"},
				EvidenceTruncated: true,
				Reason:            "detail",
			}
		})
		if len(rep.Results) != 0 || rep.TotalResults != 0 || len(rep.PrecisionLoss) != 0 || rep.EvidenceTruncated {
			t.Errorf("status %v retained analysis evidence: %+v", status, rep)
		}
	}
}

func TestRecoveredSanitizesAnalyzedEvidence(t *testing.T) {
	rep := recovered(func() Report {
		return Report{
			Status: StatusAnalyzed,
			Results: []Result{{
				Source: strings.Repeat("s", maxSegmentBytes*2),
				Via:    []string{"bad\nsegment"},
				Sink:   "ev\u202eal",
			}},
		}
	})
	if !rep.EvidenceTruncated {
		t.Fatal("EvidenceTruncated = false, want true for a shortened source")
	}
	result := rep.Results[0]
	if len(result.Source) > maxSegmentBytes || strings.ContainsAny(strings.Join(result.Via, "")+result.Sink, "\n\u202e") {
		t.Errorf("unsafe evidence escaped finalization: %+v", result)
	}
	if !utf8.ValidString(result.Source + strings.Join(result.Via, "") + result.Sink) {
		t.Errorf("evidence is not valid UTF-8: %+v", result)
	}
}
