package admission

import (
	"reflect"
	"testing"
	"time"
)

// A verified episode keeps its scheduled boundary (spec 5.2): closing it
// again, as a same-episode re-admission's verified block does, moves
// neither end, whether the new block ends sooner or later. An unusable
// reading or expiry is still refused.
func TestEpisodeCloseKeepsAnExistingBoundary(t *testing.T) {
	start := EpisodeClock{Now: t0, Elapsed: 10 * time.Hour}
	first, err := Place(nil, nil, KindBlockIP, t0, start, sequenceIDs(t))
	if err != nil {
		t.Fatal(err)
	}
	cur := first.Episode.WithLine(episodeLine(t, KindBlockIP, 1, 1))
	closed, err := cur.Close(t0.Add(time.Hour), start)
	if err != nil {
		t.Fatal(err)
	}
	later := EpisodeClock{Now: t0.Add(10 * time.Minute), Elapsed: start.Elapsed + 10*time.Minute}
	for _, again := range []time.Time{t0.Add(30 * time.Minute), t0.Add(2 * time.Hour)} {
		got, err := closed.Close(again, later)
		if err != nil || !reflect.DeepEqual(got, closed) {
			t.Fatalf("closing again at %v: %+v %v, want %+v", again, got, err, closed)
		}
	}
	if _, err := closed.Close(t0.Add(time.Hour), EpisodeClock{}); !isReason(err, ReasonInvalid) {
		t.Fatalf("closed again on an unread clock: %v", err)
	}
	if _, err := closed.Close(time.Time{}, later); !isReason(err, ReasonInvalid) {
		t.Fatalf("closed again without an expiry: %v", err)
	}
}

// Rewriting a legacy verified episode must add its missing elapsed end
// from the original boundary, even when the new block expires later.
func TestEpisodeCloseAnchorsALegacyVerifiedBoundary(t *testing.T) {
	row := testEpisodeRecord(t)
	row.Verified, row.EndElapsed = t0.Add(time.Hour), 0
	clock := EpisodeClock{Now: t0.Add(10 * time.Minute), Elapsed: 2 * time.Hour}
	got, err := row.Close(t0.Add(2*time.Hour), clock)
	want := row
	want.EndElapsed = clock.Elapsed + row.Verified.Sub(clock.Now)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy close: %+v %v, want %+v", got, err, want)
	}
}

// An answered block frontier without candidate references is retained
// proof only with a verified boundary on both clocks. It round-trips
// without resetting the generation or making the episode fresh.
func TestEpisodeRetainedBoundaryRecord(t *testing.T) {
	row := testEpisodeRecord(t)
	row.Verified, row.EndElapsed = t0.Add(time.Hour), time.Hour
	for _, line := range row.Lines {
		row, _ = row.WithoutCandidate(line.Candidate, line.Kind == KindBlockIP)
	}
	data, err := row.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalEpisode(data)
	if err != nil || !reflect.DeepEqual(got, row) {
		t.Fatalf("retained boundary did not round trip: %+v %v", got, err)
	}
	for _, change := range []func(*Episode){
		func(e *Episode) { e.Verified = time.Time{} },
		func(e *Episode) { e.EndElapsed = 0 },
		func(e *Episode) { e.Lines = nil },
		func(e *Episode) { e.Lines = append([]EpisodeLine(nil), e.Lines...); e.Lines[0].Answered = false },
	} {
		bad := row
		change(&bad)
		if _, err := bad.MarshalBinary(); !isReason(err, ReasonInvalid) {
			t.Fatalf("unproven retained boundary encoded: %+v %v", bad, err)
		}
	}
}

// A block line records the generation of its kind's latest verified block,
// so the episode can find that block after later generations are retired.
// The record round-trips and refuses a generation the line has not
// reached, an unverified episode and a kind that is not a block.
func TestEpisodeLineRecordsItsLatestVerifiedGeneration(t *testing.T) {
	row := testEpisodeRecord(t)
	row.Verified, row.EndElapsed = t0.Add(time.Hour), time.Hour
	line, _ := row.Line(KindBlockIP)
	line.VerifiedGeneration = line.Generation
	row = row.WithLine(line)
	data, err := row.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalEpisode(data)
	if err != nil || !reflect.DeepEqual(got, row) {
		t.Fatalf("verified generation did not round trip: %+v %v", got, err)
	}
	for _, change := range []func(*Episode){
		func(e *Episode) { e.Lines[0].VerifiedGeneration = e.Lines[0].Generation + 1 },
		func(e *Episode) { e.Verified, e.EndElapsed = time.Time{}, 0 },
		func(e *Episode) { e.Lines[1].VerifiedGeneration = 1 },
	} {
		bad := row
		bad.Lines = append([]EpisodeLine(nil), row.Lines...)
		change(&bad)
		if _, err := bad.MarshalBinary(); !isReason(err, ReasonInvalid) {
			t.Fatalf("unproven verified generation encoded: %+v %v", bad, err)
		}
	}
}
