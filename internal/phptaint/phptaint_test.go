package phptaint

import (
	"context"
	"testing"
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
