package admission

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func isReason(err error, want Reason) bool {
	got, ok := ReasonOf(err)
	return ok && got == want
}

func episodeLine(t *testing.T, kind Kind, gen uint32, n byte) EpisodeLine {
	t.Helper()
	return EpisodeLine{Kind: kind, Generation: gen, Candidate: testCandidateID(t, n), Observed: t0}
}

func testEpisodeRecord(t *testing.T) Episode {
	t.Helper()
	return Episode{
		ID: testEpisode(t, episodeA), Last: t0, Previous: t0.Add(-3 * time.Hour),
		Lines: []EpisodeLine{episodeLine(t, KindBlockIP, 2, 1), episodeLine(t, KindPromote, 1, 2)},
	}
}

func TestEpisodeRecordRoundTripsAndRefusesTampering(t *testing.T) {
	e := testEpisodeRecord(t)
	e.Verified = t0.Add(24 * time.Hour)
	data, err := e.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalEpisode(data)
	if err != nil {
		t.Fatal(err)
	}
	again, err := got.MarshalBinary()
	if err != nil || !bytes.Equal(again, data) || got.End() != e.Verified {
		t.Fatalf("round trip changed the record: %v %+v", err, got)
	}
	tampered := bytes.Replace(data, []byte(`"generation":2`), []byte(`"generation":3`), 1)
	if _, err = UnmarshalEpisode(tampered); !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("tampered record decoded: %v", err)
	}
}

func TestEpisodeRecordRefusesBrokenInvariants(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Episode)
	}{
		{"zero ID", func(e *Episode) { e.ID = EpisodeID{} }},
		{"no observation", func(e *Episode) { e.Last = time.Time{} }},
		{"previous episode ends after the last observation", func(e *Episode) { e.Previous = e.Last.Add(time.Second) }},
		{"no line", func(e *Episode) { e.Lines = nil }},
		{"no retained candidate", func(e *Episode) {
			for i := range e.Lines {
				e.Lines[i].Candidate = ""
			}
		}},
		{"no kind frontier", func(e *Episode) { e.Lines[0].Observed = time.Time{} }},
		{"prior observations overlap", func(e *Episode) { e.PriorLast = e.Last }},
		{"kind frontier after last", func(e *Episode) { e.Lines[0].Observed = e.Last.Add(time.Second) }},
		{"retained candidate marked answered", func(e *Episode) { e.Lines[0].Answered = true }},
		{"generation zero", func(e *Episode) { e.Lines[0].Generation = 0 }},
		{"lines out of kind order", func(e *Episode) { e.Lines[0], e.Lines[1] = e.Lines[1], e.Lines[0] }},
		{"two lines of one kind", func(e *Episode) { e.Lines[1].Kind = KindBlockIP }},
		{"unknown kind", func(e *Episode) { e.Lines[1].Kind = kindEnd }},
		{"malformed candidate", func(e *Episode) { e.Lines[0].Candidate = "cand_x" }},
	} {
		e := testEpisodeRecord(t)
		tc.edit(&e)
		if _, err := e.MarshalBinary(); err == nil {
			t.Errorf("%s: encoded", tc.name)
		}
	}
}

func TestEpisodeLinesAreKeptInKindOrder(t *testing.T) {
	e := Episode{ID: testEpisode(t, episodeA), Last: t0}
	e = e.WithLine(episodeLine(t, KindPromote, 1, 2))
	e = e.WithLine(episodeLine(t, KindBlockIP, 1, 1))
	e = e.WithLine(episodeLine(t, KindBlockIP, 2, 3))
	if len(e.Lines) != 2 || e.Lines[0] != episodeLine(t, KindBlockIP, 2, 3) || e.Lines[1].Kind != KindPromote {
		t.Fatalf("lines = %+v", e.Lines)
	}
	if _, err := e.MarshalBinary(); err != nil {
		t.Fatal(err)
	}
	rest, found := e.WithoutCandidate(testCandidateID(t, 3), false)
	if !found || len(rest.Lines) != 2 || rest.Lines[0].Candidate != "" || rest.Lines[0].Generation != 2 || rest.Lines[1].Kind != KindPromote {
		t.Fatalf("without the block line: %v %+v", found, rest.Lines)
	}
	if _, found = rest.WithoutCandidate(testCandidateID(t, 3), false); found {
		t.Fatal("a removed line was found again")
	}
	if line, ok := e.Line(KindPromote); !ok || line.Candidate != testCandidateID(t, 2) {
		t.Fatalf("promote line = %+v %v", line, ok)
	}
}

func TestLineStateFollowsTheCandidate(t *testing.T) {
	c := queuedCandidate(t)
	for _, tc := range []struct {
		state    State
		attempts uint32
		want     LineState
	}{
		{StateQueued, 0, LineQueued},
		{StateQueued, 1, LineRetry},
		{StateReserved, 1, LineInFlight},
		{StateExecuting, 1, LineInFlight},
		{StateVerified, 1, LineAnswered},
		{StateFailed, 3, LineAnswered},
		{StateUnknown, 1, LineAnswered},
		{StateObserved, 1, LineAnswered},
		{StateDropped, 0, LineEnded},
		{StateRefused, 0, LineEnded},
		{StateWithheld, 0, LineEnded},
	} {
		c.State, c.Attempts = tc.state, tc.attempts
		if got := LineStateOf(c); got != tc.want {
			t.Errorf("%v with %d attempts: %v, want %v", tc.state, tc.attempts, got, tc.want)
		}
	}
}

// testSequence names the episodes the tests open, never twice.
var testSequence = EpisodeSequence{Nonce: [16]byte{0xee}}

func sequenceIDs(t *testing.T) func() (EpisodeID, error) {
	t.Helper()
	return testSequence.Take
}

func place(t *testing.T, cur *Episode, states []LineState, kind Kind, at time.Time, degraded bool) EpisodeChoice {
	t.Helper()
	p, err := Place(cur, states, kind, at, degraded, sequenceIDs(t))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// An episode lasts while observations keep coming, ends an hour after the
// last one, and the next observation after that starts a new one (spec 5.2).
func TestPlaceOpensJoinsAndEndsEpisodes(t *testing.T) {
	first := place(t, nil, nil, KindBlockIP, t0, false)
	if first.Generation != 1 || first.Answered || first.Episode.ID.IsZero() || !first.Episode.Last.Equal(t0) || !first.Episode.Previous.IsZero() {
		t.Fatalf("first observation: %+v", first)
	}
	cur := first.Episode.WithLine(episodeLine(t, KindBlockIP, 1, 1))

	later := place(t, &cur, []LineState{LineEnded}, KindBlockIP, t0.Add(EpisodeQuiet-time.Second), false)
	if later.Episode.ID != cur.ID || later.Generation != 2 || !later.Episode.Last.Equal(t0.Add(EpisodeQuiet-time.Second)) {
		t.Fatalf("an observation inside the hour must start the next generation: %+v", later)
	}
	if late := place(t, &cur, []LineState{LineQueued}, KindBlockIP, t0.Add(-time.Minute), false); late.Episode.ID != cur.ID || !late.Episode.Last.Equal(t0) || late.Generation != 1 {
		t.Fatalf("an earlier observation must join without moving the last one back: %+v", late)
	}
	other := place(t, &cur, []LineState{LineAnswered}, KindPromote, t0.Add(time.Minute), false)
	if other.Episode.ID != cur.ID || other.Generation != 1 || other.Answered {
		t.Fatalf("another kind joins the episode with its own first generation: %+v", other)
	}

	next := place(t, &cur, []LineState{LineEnded}, KindBlockIP, t0.Add(EpisodeQuiet), false)
	if next.Episode.ID == cur.ID || next.Generation != 1 || !next.Episode.Previous.Equal(t0.Add(EpisodeQuiet)) || len(next.Episode.Lines) != 0 {
		t.Fatalf("an observation an hour after the last must open the next episode: %+v", next)
	}
	if _, err := Place(&next.Episode, nil, KindBlockIP, t0.Add(EpisodeQuiet-time.Nanosecond), false, sequenceIDs(t)); !isReason(err, ReasonStale) {
		t.Fatalf("an observation of the previous episode: %v", err)
	}
}

// Work still queued or in flight keeps its episode open however long the
// quiet, and a degraded clock never ends one by wall time alone.
func TestPlaceKeepsAnEpisodeWithLiveWorkOrAnUntrustedClock(t *testing.T) {
	cur := place(t, nil, nil, KindBlockIP, t0, false).Episode.WithLine(episodeLine(t, KindBlockIP, 1, 1))
	cur = cur.WithLine(episodeLine(t, KindPromote, 1, 2))
	gap := t0.Add(3 * EpisodeQuiet)
	for _, tc := range []struct {
		name     string
		states   []LineState
		degraded bool
	}{
		{"queued line", []LineState{LineQueued, LineEnded}, false},
		{"queued retry", []LineState{LineRetry, LineEnded}, false},
		{"line of another kind in flight", []LineState{LineEnded, LineInFlight}, false},
		{"degraded clock", []LineState{LineEnded, LineEnded}, true},
	} {
		p := place(t, &cur, tc.states, KindBlockIP, gap, tc.degraded)
		if p.Episode.ID != cur.ID || !p.Episode.Last.Equal(gap) {
			t.Errorf("%s: %+v", tc.name, p)
		}
	}
}

// Once a line has an attempt, later observations extend the episode but
// queue nothing more of that kind until it ends.
func TestPlaceAnswersAnAttemptedLine(t *testing.T) {
	cur := place(t, nil, nil, KindBlockIP, t0, false).Episode.WithLine(episodeLine(t, KindBlockIP, 4, 1))
	for _, state := range []LineState{LineRetry, LineInFlight, LineAnswered} {
		p := place(t, &cur, []LineState{state}, KindBlockIP, t0.Add(30*time.Minute), false)
		if !p.Answered || p.Generation != 4 || p.Episode.ID != cur.ID || !p.Episode.Last.Equal(t0.Add(30*time.Minute)) {
			t.Errorf("%v: %+v", state, p)
		}
	}
}

// A verified response ends its episode at its original expiry, not an hour
// after the last observation (spec 5.2).
func TestPlaceEndsAVerifiedEpisodeAtItsExpiry(t *testing.T) {
	cur := place(t, nil, nil, KindBlockIP, t0, false).Episode.WithLine(episodeLine(t, KindBlockIP, 1, 1))
	cur.Verified = t0.Add(20 * time.Minute)
	cur.Last = t0.Add(19 * time.Minute)
	if p := place(t, &cur, []LineState{LineAnswered}, KindBlockIP, t0.Add(20*time.Minute-time.Nanosecond), false); !p.Answered || p.Episode.ID != cur.ID {
		t.Fatalf("before the expiry: %+v", p)
	}
	p := place(t, &cur, []LineState{LineAnswered}, KindBlockIP, t0.Add(20*time.Minute), false)
	if p.Answered || p.Episode.ID == cur.ID || p.Generation != 1 || !p.Episode.Previous.Equal(cur.Verified) {
		t.Fatalf("at the expiry the next episode must open: %+v", p)
	}
	cur.Verified = t0.Add(5 * time.Hour)
	if p = place(t, &cur, []LineState{LineAnswered}, KindBlockIP, t0.Add(2*time.Hour), false); !p.Answered || p.Episode.ID != cur.ID {
		t.Fatalf("a long block keeps its episode past the quiet hour: %+v", p)
	}
}

func TestPlaceRefusesBadInput(t *testing.T) {
	cur := place(t, nil, nil, KindBlockIP, t0, false).Episode.WithLine(episodeLine(t, KindBlockIP, math.MaxUint32, 1))
	for _, tc := range []struct {
		name   string
		cur    *Episode
		states []LineState
		kind   Kind
		at     time.Time
	}{
		{"unknown kind", nil, nil, kindEnd, t0},
		{"no observation time", nil, nil, KindBlockIP, time.Time{}},
		{"states do not match the lines", &cur, nil, KindBlockIP, t0},
		{"unknown line state", &cur, []LineState{0}, KindBlockIP, t0},
		{"generations exhausted", &cur, []LineState{LineEnded}, KindBlockIP, t0},
	} {
		if _, err := Place(tc.cur, tc.states, tc.kind, tc.at, false, sequenceIDs(t)); !isReason(err, ReasonInvalid) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	broken := func() (EpisodeID, error) { return EpisodeID{}, ErrCorruptRecord }
	if _, err := Place(nil, nil, KindBlockIP, t0, false, broken); !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("a failed ID must fail the placement: %v", err)
	}
}

// A report accepted while another kind holds an episode past its
// verified expiry is still that episode's report when work finally ends.
func TestPlaceKeepsPriorEpisodeObservationProof(t *testing.T) {
	cur := testEpisodeRecord(t)
	cur.Verified, cur.Last = t0.Add(20*time.Minute), t0.Add(25*time.Minute)
	if _, err := Place(&cur, []LineState{LineAnswered, LineEnded}, KindBlockIP, cur.Last, false, sequenceIDs(t)); !isReason(err, ReasonStale) {
		t.Fatalf("old report opened another episode: %v", err)
	}
	next := place(t, &cur, []LineState{LineAnswered, LineEnded}, KindBlockIP, t0.Add(26*time.Minute), false)
	if !next.Episode.Previous.Equal(cur.Verified) || !next.Episode.PriorLast.Equal(cur.Last) {
		t.Fatalf("original expiry or prior observation proof was lost: %+v", next)
	}
	if _, err := Place(&next.Episode, nil, KindBlockIP, cur.Last, false, sequenceIDs(t)); !isReason(err, ReasonStale) {
		t.Fatalf("old report joined the next episode: %v", err)
	}
}

// Cleared lines retain their counters and attempted state. Repeated or
// older roots cannot advance an ended generation, even after deletion.
func TestPlaceRetainsDeletedEpisodeLineProof(t *testing.T) {
	cur := testEpisodeRecord(t)
	cleared, ok := cur.WithoutCandidate(cur.Lines[0].Candidate, false)
	if !ok || !cleared.HasCandidates() || cleared.Lines[0].Candidate != "" || cleared.Lines[0].Generation != 2 {
		t.Fatalf("cleared line lost its proof: %+v", cleared)
	}
	for _, at := range []time.Time{t0, t0.Add(-time.Second)} {
		if _, err := Place(&cleared, []LineState{LineEnded, LineQueued}, KindBlockIP, at, false, sequenceIDs(t)); !isReason(err, ReasonStale) {
			t.Errorf("repeated observation advanced a cleared line: %v", err)
		}
	}
	p := place(t, &cleared, []LineState{LineEnded, LineQueued}, KindBlockIP, t0.Add(time.Second), false)
	if p.Generation != 3 || p.Episode.ID != cur.ID {
		t.Fatalf("later observation lost the generation: %+v", p)
	}
	answered, _ := cur.WithoutCandidate(cur.Lines[0].Candidate, true)
	data, err := answered.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalEpisode(data)
	if err != nil || !decoded.Lines[0].Answered || decoded.Lines[0].Generation != 2 {
		t.Fatalf("cleared attempt proof did not round trip: %+v %v", decoded, err)
	}
	if p := place(t, &decoded, []LineState{LineAnswered, LineQueued}, KindBlockIP, t0.Add(time.Second), false); !p.Answered || p.Generation != 2 {
		t.Fatalf("a cleared attempted line admitted more work: %+v", p)
	}
}

func TestEpisodeWithoutCandidateIgnoresAnEmptyID(t *testing.T) {
	e := testEpisodeRecord(t)
	e, _ = e.WithoutCandidate(e.Lines[0].Candidate, true)
	before, err := e.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	rest, found := e.WithoutCandidate("", false)
	after, err := rest.MarshalBinary()
	if err != nil || found || !bytes.Equal(before, after) {
		t.Fatalf("an empty ID changed cleared attempt proof: %+v %v %v", rest, found, err)
	}
}

// Episode IDs come from a per-ledger nonce and a sequence, so they never
// repeat within a ledger or across ledgers.
func TestEpisodeSequenceHandsOutDistinctIDs(t *testing.T) {
	a := EpisodeSequence{Nonce: [16]byte{1}}
	b := EpisodeSequence{Nonce: [16]byte{2}}
	seen := map[EpisodeID]bool{}
	for i := 0; i < 3; i++ {
		for _, s := range []*EpisodeSequence{&a, &b} {
			id, err := s.Take()
			if err != nil || id.IsZero() || seen[id] {
				t.Fatalf("take %d: %v %v", i, id, err)
			}
			seen[id] = true
		}
	}
	if a.Next != 3 {
		t.Fatalf("next = %d", a.Next)
	}
	data, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalEpisodeSequence(data)
	if err != nil || got != a {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if _, err = UnmarshalEpisodeSequence(bytes.Replace(data, []byte(`"next":3`), []byte(`"next":2`), 1)); !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("tampered sequence decoded: %v", err)
	}
	if _, err = (EpisodeSequence{}).MarshalBinary(); err == nil {
		t.Fatal("a zero nonce encoded")
	}
	last := EpisodeSequence{Nonce: [16]byte{1}, Next: math.MaxUint64}
	if _, err = last.Take(); !isReason(err, ReasonInvalid) || last.Next != math.MaxUint64 {
		t.Fatalf("an exhausted sequence: %v %d", err, last.Next)
	}
	fresh, err := NewEpisodeSequence(strings.NewReader(strings.Repeat("\x07", 16)))
	if err != nil || fresh.Nonce != [16]byte{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7} || fresh.Next != 0 {
		t.Fatalf("new sequence: %+v %v", fresh, err)
	}
	if _, err = NewEpisodeSequence(strings.NewReader("short")); err == nil {
		t.Fatal("a short nonce read was accepted")
	}
}

// Storage accounting charges each stored episode row its bound, so the
// widest row the invariants allow must fit it.
func TestEpisodeRowFitsItsBound(t *testing.T) {
	for _, nano := range []int64{math.MaxInt64, math.MinInt64 + 1} {
		e := Episode{ID: testEpisode(t, episodeA), Last: time.Unix(0, nano).UTC(), Verified: time.Unix(0, nano).UTC(), Previous: time.Unix(0, nano).UTC(), PriorLast: time.Unix(0, nano-1).UTC()}
		for k := KindBlockIP; k < kindEnd; k++ {
			e = e.WithLine(EpisodeLine{Kind: k, Generation: math.MaxUint32, Candidate: testCandidateID(t, 15), Observed: e.Last})
		}
		data, err := e.MarshalBinary()
		widest := len("svc:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/udp/65535")
		if err != nil || widest > MaxEpisodeKeyBytes || len(data)+MaxEpisodeKeyBytes > MaxEpisodeBytes {
			t.Fatalf("widest row at %d: key %d of %d, record %d, bound %d, %v", nano, widest, MaxEpisodeKeyBytes, len(data), MaxEpisodeBytes, err)
		}
	}
}

// episodeGolden is the first ID of the sequence with nonce 01 00 .. 00.
const episodeGolden = "dee8d389fee4f80d3bc3e0fc1a214cea"

// The ledger stores these IDs. A change to the derivation must bump
// identityVersion and this golden value together.
func TestEpisodeIDsAreFrozen(t *testing.T) {
	s := EpisodeSequence{Nonce: [16]byte{1}}
	id, err := s.Take()
	if err != nil || id.String() != episodeGolden {
		t.Fatalf("episode ID = %v %v", id, err)
	}
}
