package jstaint

import (
	"context"
	"strings"
	"testing"
)

// A converging diamond reaches one sink through two branches but is a single
// endpoint flow, counted once without enumerating every route.
func TestCaps_ConvergingDiamondCountsOneFlow(t *testing.T) {
	src := `document.onkeydown=function(e){var k=e.key;var m=window.p?k:k;fetch("/c?x="+m);};`
	got := analyzeSrc(t, src)
	if got.TotalResults != 1 || len(got.Results) != 1 {
		t.Fatalf("TotalResults=%d len(Results)=%d, want 1 and 1", got.TotalResults, len(got.Results))
	}
	if got.EvidenceTruncated {
		t.Errorf("EvidenceTruncated=true for a single short flow")
	}
}

// More than eight distinct endpoint flows are capped to eight evidence paths,
// while TotalResults reports the true count and EvidenceTruncated is set.
func TestCaps_MoreThanEightFlowsAreCapped(t *testing.T) {
	var b strings.Builder
	b.WriteString(`document.onkeydown=function(e){`)
	const flows = 11
	for i := 0; i < flows; i++ {
		b.WriteString(`fetch("/c` + itoa(i) + `?k="+e.key);`)
	}
	b.WriteString(`};`)
	got := analyzeSrc(t, b.String())
	if got.TotalResults != flows {
		t.Fatalf("TotalResults=%d, want %d", got.TotalResults, flows)
	}
	if len(got.Results) != 8 {
		t.Fatalf("len(Results)=%d, want 8 (evidence cap)", len(got.Results))
	}
	if !got.EvidenceTruncated {
		t.Errorf("EvidenceTruncated=false, want true when flows exceed the cap")
	}
}

// A long laundering chain truncates its Via evidence to 32 segments: the first 16,
// a bounded middle marker naming the omitted count, and the final 15.
func TestCaps_LongViaChainTruncatesTo32Segments(t *testing.T) {
	const hops = 100
	var b strings.Builder
	b.WriteString(`document.onkeydown=function(e){var v0=e.key;`)
	for i := 1; i < hops; i++ {
		b.WriteString(`var v` + itoa(i) + `=v` + itoa(i-1) + `;`)
	}
	b.WriteString(`fetch("/c?k="+v` + itoa(hops-1) + `);};`)
	r := firstResult(t, b.String())
	if len(r.Via) != 32 {
		t.Fatalf("len(Via)=%d, want 32", len(r.Via))
	}
	if r.Via[0] != "v0" || r.Via[31] != "v99" {
		t.Errorf("Via endpoints = %q..%q, want v0..v99", r.Via[0], r.Via[31])
	}
	marker := r.Via[16]
	if !strings.Contains(marker, "omitted") {
		t.Errorf("middle segment %q is not an omission marker", marker)
	}
	// 100 segments, 31 retained, so 69 are omitted.
	if !strings.Contains(marker, "69") {
		t.Errorf("omission marker %q does not state the 69 omitted segments", marker)
	}
	if !analyzeSrc(t, b.String()).EvidenceTruncated {
		t.Errorf("EvidenceTruncated=false, want true for a truncated chain")
	}
}

// A single laundering segment longer than the per-segment byte cap is shortened
// with a marker, and the shortening sets EvidenceTruncated.
func TestCaps_OversizeViaSegmentIsBounded(t *testing.T) {
	long := strings.Repeat("z", 200)
	src := `document.onkeydown=function(e){var ` + long + `=e.key;fetch("/c?k="+` + long + `);};`
	got := analyzeSrc(t, src)
	if len(got.Results) == 0 {
		t.Fatal("no flow detected")
	}
	seg := got.Results[0].Via[0]
	if len(seg) > 64 {
		t.Errorf("Via segment is %d bytes, want at most 64", len(seg))
	}
	if !got.EvidenceTruncated {
		t.Errorf("EvidenceTruncated=false, want true when a segment is shortened")
	}
}

// Output is deterministic across runs even though internal maps iterate in random
// order.
func TestCaps_ResultsAreDeterministic(t *testing.T) {
	var b strings.Builder
	b.WriteString(`document.onkeydown=function(e){`)
	for i := 0; i < 12; i++ {
		b.WriteString(`fetch("/c` + itoa(i) + `?k="+e.key);`)
	}
	b.WriteString(`};`)
	src := []byte(b.String())
	first := Analyze(context.Background(), src)
	for i := 0; i < 20; i++ {
		got := Analyze(context.Background(), src)
		if got.TotalResults != first.TotalResults || len(got.Results) != len(first.Results) {
			t.Fatalf("run %d differs in counts", i)
		}
		for j := range got.Results {
			g, f := got.Results[j], first.Results[j]
			if g.Source != f.Source || g.Sink != f.Sink || strings.Join(g.Via, "\x00") != strings.Join(f.Via, "\x00") {
				t.Fatalf("run %d result %d = %+v, want %+v", i, j, g, f)
			}
		}
	}
}
