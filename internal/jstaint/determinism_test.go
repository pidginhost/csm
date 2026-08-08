package jstaint

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
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
		b.WriteString(`var v` + itoa(i) + `=e.key;fetch("/c` + itoa(i) + `?k="+v` + itoa(i) + `);`)
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
	wantVia := []string{"v0", "v1", "v10", "v2", "v3", "v4", "v5", "v6"}
	for i, want := range wantVia {
		if len(got.Results[i].Via) != 1 || got.Results[i].Via[0] != want {
			t.Errorf("Results[%d].Via=%q, want [%q]", i, got.Results[i].Via, want)
		}
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
	if marker := r.Via[16]; marker != "[69 segments omitted]" {
		t.Errorf("middle segment = %q, want exact omission marker", marker)
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
	if len(seg) != maxSegmentBytes || !strings.HasSuffix(seg, "...") {
		t.Errorf("Via segment = %q (%d bytes), want a %d-byte marked segment", seg, len(seg), maxSegmentBytes)
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
		b.WriteString(`var v` + itoa(i) + `=e.key;fetch("/c` + itoa(i) + `?k="+v` + itoa(i) + `);`)
	}
	b.WriteString(`};`)
	src := []byte(b.String())
	first := Analyze(context.Background(), src)
	for i := 0; i < 20; i++ {
		got := Analyze(context.Background(), src)
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d = %#v, want %#v", i, got, first)
		}
	}
}

func TestCaps_ExactViaBoundaryIsNotTruncated(t *testing.T) {
	via := make([]string, maxViaSegments)
	for i := range via {
		via[i] = "v" + itoa(i)
	}
	got, truncated := truncateVia(via)
	if truncated {
		t.Fatal("truncateVia reported truncation at the exact segment limit")
	}
	if !reflect.DeepEqual(got, via) {
		t.Fatalf("truncateVia = %q, want %q", got, via)
	}
}

func TestCaps_FirstOverViaBoundaryUsesExactHeadAndTail(t *testing.T) {
	via := make([]string, maxViaSegments+1)
	for i := range via {
		via[i] = "v" + itoa(i)
	}
	got, truncated := truncateVia(via)
	if !truncated {
		t.Fatal("truncateVia did not report truncation above the segment limit")
	}
	if len(got) != maxViaSegments {
		t.Fatalf("len(Via)=%d, want %d", len(got), maxViaSegments)
	}
	if got[15] != "v15" || got[16] != "[2 segments omitted]" || got[17] != "v18" || got[31] != "v32" {
		t.Fatalf("Via boundary = %q, want v15, marker, v18 through v32", got[15:])
	}
}

func TestCaps_BoundSegmentCutsBeforeMultibyteRune(t *testing.T) {
	segment := strings.Repeat("a", 59) + strings.Repeat("\u00e9", 3)
	got, truncated := boundSegment(segment)
	want := strings.Repeat("a", 59) + "\u00e9..."
	if !truncated {
		t.Fatal("boundSegment did not report truncation above the byte limit")
	}
	if got != want || len(got) != maxSegmentBytes || !utf8.ValidString(got) {
		t.Fatalf("boundSegment = %q (%d bytes, valid=%t), want %q", got, len(got), utf8.ValidString(got), want)
	}
}

func TestCaps_SanitizesEachInvalidAndControlByte(t *testing.T) {
	got, truncated := boundSegment("a\xff\xfe\x00\nb\uFFFD")
	if truncated {
		t.Fatal("boundSegment reported truncation for sanitization below the byte limit")
	}
	if want := "a????b\uFFFD"; got != want {
		t.Fatalf("boundSegment = %q, want %q", got, want)
	}
}

func TestCaps_InvalidByteRunStillHonorsLengthCap(t *testing.T) {
	got, truncated := boundSegment(strings.Repeat("\xff", maxSegmentBytes+1))
	want := strings.Repeat("?", maxSegmentBytes-len("...")) + "..."
	if !truncated {
		t.Fatal("boundSegment did not report truncation for an oversize invalid-byte run")
	}
	if got != want {
		t.Fatalf("boundSegment = %q (%d bytes), want %q", got, len(got), want)
	}
}

func TestCaps_SortsBySourceViaAndSink(t *testing.T) {
	want := []Result{
		{Source: "a", Via: []string{"a"}, Sink: "a"},
		{Source: "a", Via: []string{"a"}, Sink: "b"},
		{Source: "a", Via: []string{"b"}, Sink: "a"},
		{Source: "b", Via: []string{"a"}, Sink: "a"},
	}
	a := analysis{results: map[flowKey]Result{}}
	for i := len(want) - 1; i >= 0; i-- {
		a.results[flowKey{source: i}] = want[i]
	}
	got, total, truncated := a.finalizeResults()
	if total != len(want) || truncated {
		t.Fatalf("TotalResults=%d EvidenceTruncated=%t, want %d and false", total, truncated, len(want))
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Results = %#v, want %#v", got, want)
	}
}

func TestCaps_DisplayTruncationDoesNotMergeDistinctFlows(t *testing.T) {
	common := strings.Repeat("s", maxSegmentBytes)
	a := analysis{results: map[flowKey]Result{
		{source: 0}: {Source: common + "a", Sink: sinkFetchURL},
		{source: 1}: {Source: common + "b", Sink: sinkFetchURL},
	}}
	got, total, truncated := a.finalizeResults()
	if total != 2 || len(got) != 2 {
		t.Fatalf("TotalResults=%d len(Results)=%d, want 2 and 2", total, len(got))
	}
	if !truncated {
		t.Fatal("EvidenceTruncated=false, want true for shortened source segments")
	}
	if got[0].Source != got[1].Source || len(got[0].Source) != maxSegmentBytes || !strings.HasSuffix(got[0].Source, "...") {
		t.Fatalf("bounded Sources = %q and %q, want two identical marked displays", got[0].Source, got[1].Source)
	}
	if got[0].Via != nil || got[1].Via != nil {
		t.Fatalf("direct flows gained Via evidence: %#v", got)
	}
}

func TestCaps_BoundsSourceAndSinkSegments(t *testing.T) {
	a := analysis{results: map[flowKey]Result{
		{}: {
			Source: strings.Repeat("s", maxSegmentBytes+1),
			Sink:   strings.Repeat("k", maxSegmentBytes+1),
		},
	}}
	got, total, truncated := a.finalizeResults()
	if total != 1 || len(got) != 1 || !truncated {
		t.Fatalf("TotalResults=%d len(Results)=%d EvidenceTruncated=%t, want 1, 1, true", total, len(got), truncated)
	}
	if len(got[0].Source) != maxSegmentBytes || !strings.HasSuffix(got[0].Source, "...") {
		t.Errorf("Source = %q, want a %d-byte marked segment", got[0].Source, maxSegmentBytes)
	}
	if len(got[0].Sink) != maxSegmentBytes || !strings.HasSuffix(got[0].Sink, "...") {
		t.Errorf("Sink = %q, want a %d-byte marked segment", got[0].Sink, maxSegmentBytes)
	}
}
