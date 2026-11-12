package admission

import (
	"bytes"
	"errors"
	"math"
	"slices"
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
		{"negative elapsed end", func(e *Episode) { e.EndElapsed = -time.Nanosecond }},
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

// A line answers its kind while its outcome holds the target: a verified
// block or an observe preview. An unknown outcome is unresolved until
// recovery retires it (I2). A final failure, a retired unknown outcome and
// a queue ending let a later observation start the next generation.
func TestLineStateFollowsTheCandidate(t *testing.T) {
	c := queuedCandidate(t)
	for _, tc := range []struct {
		state    State
		attempts uint32
		retired  bool
		want     LineState
	}{
		{StateQueued, 0, false, LineQueued},
		{StateQueued, 1, false, LineRetry},
		{StateReserved, 1, false, LineInFlight},
		{StateExecuting, 1, false, LineInFlight},
		{StateVerified, 1, false, LineAnswered},
		{StateObserved, 1, false, LineAnswered},
		{StateUnknown, 1, false, LineUnresolved},
		{StateUnknown, 1, true, LineEnded},
		{StateFailed, 3, false, LineEnded},
		{StateDropped, 1, false, LineEnded},
		{StateDropped, 0, false, LineEnded},
		{StateRefused, 0, false, LineEnded},
		{StateWithheld, 0, false, LineEnded},
		{StateDryRun, 0, false, LineEnded},
		{StateDryRun, 1, false, LineEnded},
	} {
		c.State, c.Attempts = tc.state, tc.attempts
		if got := LineStateOf(c, tc.retired); got != tc.want {
			t.Errorf("%v with %d attempts, retired %v: %v, want %v", tc.state, tc.attempts, tc.retired, got, tc.want)
		}
	}
}

// testSequence names the episodes the tests open, never twice.
var testSequence = EpisodeSequence{Nonce: [16]byte{0xee}}

func sequenceIDs(t *testing.T) func() (EpisodeID, error) {
	t.Helper()
	return testSequence.Take
}

// clockEpoch is when the tests' elapsed time starts, well before any
// observation they place.
var clockEpoch = t0.Add(-30 * 24 * time.Hour)

// wallClock reads at with elapsed time keeping pace with the wall, so an
// episode ends as the wall alone would end it.
func wallClock(at time.Time, degraded bool) EpisodeClock {
	return EpisodeClock{Now: at, Elapsed: at.Sub(clockEpoch), Degraded: degraded}
}

func place(t *testing.T, cur *Episode, states []LineState, kind Kind, at time.Time, degraded bool) EpisodeChoice {
	t.Helper()
	p, err := Place(cur, states, kind, at, wallClock(at, degraded), sequenceIDs(t))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// An episode lasts while observations keep coming, ends an hour after the
// last one, and the next observation after that starts a new one.
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
	if _, err := Place(&next.Episode, nil, KindBlockIP, t0.Add(EpisodeQuiet-time.Nanosecond), wallClock(t0.Add(EpisodeQuiet), false), sequenceIDs(t)); !isReason(err, ReasonStale) {
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

// I2: an unresolved line answers its kind and holds the episode open, but
// the observation it answers neither extends the episode nor moves the
// line's frontier. Another kind's observation still extends the episode.
// Once the line is retired, a later observation opens the next episode.
func TestPlaceHoldsAnUnresolvedLineWithoutExtending(t *testing.T) {
	cur := place(t, nil, nil, KindBlockIP, t0, false).Episode.WithLine(episodeLine(t, KindBlockIP, 2, 1))
	cur = cur.WithLine(episodeLine(t, KindPromote, 1, 2))
	gap := t0.Add(3 * EpisodeQuiet)
	p := place(t, &cur, []LineState{LineUnresolved, LineEnded}, KindBlockIP, gap, false)
	if !p.Answered || p.Generation != 2 || p.Episode.ID != cur.ID || !p.Episode.Last.Equal(cur.Last) || !slices.Equal(p.Episode.Lines, cur.Lines) {
		t.Fatalf("answered by an unresolved line: %+v", p)
	}
	other := place(t, &cur, []LineState{LineUnresolved, LineEnded}, KindPromote, gap, false)
	if other.Answered || other.Episode.ID != cur.ID || !other.Episode.Last.Equal(gap) || other.Generation != 2 {
		t.Fatalf("another kind: %+v", other)
	}
	next := place(t, &cur, []LineState{LineEnded, LineEnded}, KindBlockIP, gap, false)
	if next.Episode.ID == cur.ID || next.Generation != 1 {
		t.Fatalf("after retirement: %+v", next)
	}
}

// verifiedAt closes e at a block's expiry on a wall-paced clock read at
// t0, as the ledger closes an episode when the block is verified.
func verifiedAt(t *testing.T, e Episode, expiry time.Time) Episode {
	t.Helper()
	closed, err := e.Close(expiry, wallClock(t0, false))
	if err != nil {
		t.Fatal(err)
	}
	return closed
}

func TestPlaceEndsAVerifiedEpisodeAtItsExpiry(t *testing.T) {
	cur := place(t, nil, nil, KindBlockIP, t0, false).Episode.WithLine(episodeLine(t, KindBlockIP, 1, 1))
	cur = verifiedAt(t, cur, t0.Add(20*time.Minute))
	cur.Last = t0.Add(19 * time.Minute)
	if p := place(t, &cur, []LineState{LineAnswered}, KindBlockIP, t0.Add(20*time.Minute-time.Nanosecond), false); !p.Answered || p.Episode.ID != cur.ID {
		t.Fatalf("before the expiry: %+v", p)
	}
	p := place(t, &cur, []LineState{LineAnswered}, KindBlockIP, t0.Add(20*time.Minute), false)
	if p.Answered || p.Episode.ID == cur.ID || p.Generation != 1 || !p.Episode.Previous.Equal(cur.Verified) {
		t.Fatalf("at the expiry the next episode must open: %+v", p)
	}
	// A verified episode keeps its boundary, so a long block is a fresh
	// episode of its own.
	long := verifiedAt(t, place(t, nil, nil, KindBlockIP, t0, false).Episode.WithLine(episodeLine(t, KindBlockIP, 1, 1)), t0.Add(5*time.Hour))
	if p = place(t, &long, []LineState{LineAnswered}, KindBlockIP, t0.Add(2*time.Hour), false); !p.Answered || p.Episode.ID != long.ID {
		t.Fatalf("a long block keeps its episode past the quiet hour: %+v", p)
	}
}

// I1: a verified block ends its episode at its expiry even while another
// kind's work is queued or in flight. An unresolved line and a degraded
// clock still hold it.
func TestPlaceEndsAVerifiedEpisodeDespiteOtherWork(t *testing.T) {
	cur := place(t, nil, nil, KindBlockIP, t0, false).Episode.WithLine(episodeLine(t, KindBlockIP, 1, 1))
	cur = cur.WithLine(episodeLine(t, KindChallenge, 1, 2))
	cur = verifiedAt(t, cur, t0.Add(20*time.Minute))
	cur.Last = t0.Add(19 * time.Minute)
	expiry := cur.Verified
	for _, state := range []LineState{LineQueued, LineRetry, LineInFlight} {
		if p := place(t, &cur, []LineState{LineAnswered, state}, KindBlockIP, expiry.Add(-time.Nanosecond), false); !p.Answered || p.Episode.ID != cur.ID {
			t.Fatalf("%v before the expiry: %+v", state, p)
		}
		p := place(t, &cur, []LineState{LineAnswered, state}, KindBlockIP, expiry, false)
		if p.Answered || p.Episode.ID == cur.ID || p.Generation != 1 || !p.Episode.Previous.Equal(expiry) {
			t.Fatalf("%v at the expiry: %+v", state, p)
		}
	}
	later := expiry.Add(2 * time.Hour)
	if p := place(t, &cur, []LineState{LineAnswered, LineUnresolved}, KindBlockIP, later, false); !p.Answered || p.Episode.ID != cur.ID {
		t.Fatalf("an unresolved line: %+v", p)
	}
	if p := place(t, &cur, []LineState{LineAnswered, LineQueued}, KindBlockIP, later, true); !p.Answered || p.Episode.ID != cur.ID {
		t.Fatalf("a degraded clock: %+v", p)
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
		if _, err := Place(tc.cur, tc.states, tc.kind, tc.at, wallClock(t0, false), sequenceIDs(t)); !isReason(err, ReasonInvalid) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	broken := func() (EpisodeID, error) { return EpisodeID{}, ErrCorruptRecord }
	if _, err := Place(nil, nil, KindBlockIP, t0, wallClock(t0, false), broken); !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("a failed ID must fail the placement: %v", err)
	}
}

// A report accepted while another kind holds an episode past its
// verified expiry is still that episode's report when work finally ends.
func TestPlaceKeepsPriorEpisodeObservationProof(t *testing.T) {
	cur := testEpisodeRecord(t)
	cur.Verified, cur.Last = t0.Add(20*time.Minute), t0.Add(25*time.Minute)
	if _, err := Place(&cur, []LineState{LineAnswered, LineEnded}, KindBlockIP, cur.Last, wallClock(cur.Last, false), sequenceIDs(t)); !isReason(err, ReasonStale) {
		t.Fatalf("old report opened another episode: %v", err)
	}
	next := place(t, &cur, []LineState{LineAnswered, LineEnded}, KindBlockIP, t0.Add(26*time.Minute), false)
	if !next.Episode.Previous.Equal(cur.Verified) || !next.Episode.PriorLast.Equal(cur.Last) {
		t.Fatalf("original expiry or prior observation proof was lost: %+v", next)
	}
	if _, err := Place(&next.Episode, nil, KindBlockIP, cur.Last, wallClock(t0.Add(26*time.Minute), false), sequenceIDs(t)); !isReason(err, ReasonStale) {
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
		if _, err := Place(&cleared, []LineState{LineEnded, LineQueued}, KindBlockIP, at, wallClock(t0, false), sequenceIDs(t)); !isReason(err, ReasonStale) {
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
		e := Episode{ID: testEpisode(t, episodeA), Last: time.Unix(0, nano).UTC(), Verified: time.Unix(0, nano).UTC(), EndElapsed: math.MaxInt64, Previous: time.Unix(0, nano).UTC(), PriorLast: time.Unix(0, nano-1).UTC()}
		for k := KindBlockIP; k < kindEnd; k++ {
			line := EpisodeLine{Kind: k, Generation: math.MaxUint32, Candidate: testCandidateID(t, 15), Observed: e.Last}
			if k == KindBlockIP || k == KindBlockSubnet {
				line.VerifiedGeneration = math.MaxUint32
			}
			e = e.WithLine(line)
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

// An elapsed end round-trips; a row without one keeps the bytes it had
// before elapsed ends existed.
func TestEpisodeRecordCarriesItsElapsedEnd(t *testing.T) {
	e := testEpisodeRecord(t)
	plain, err := e.MarshalBinary()
	if err != nil || bytes.Contains(plain, []byte("end_elapsed")) {
		t.Fatalf("a row without an elapsed end: %s, %v", plain, err)
	}
	e.EndElapsed = 90 * time.Minute
	data, err := e.MarshalBinary()
	if err != nil || !bytes.Contains(data, []byte(`"end_elapsed":5400000000000`)) {
		t.Fatalf("encoded %s, %v", data, err)
	}
	got, err := UnmarshalEpisode(data)
	if err != nil || got.EndElapsed != e.EndElapsed {
		t.Fatalf("decoded %+v, %v", got, err)
	}
}

// I3: an episode ends only once the wall and the ceiling's elapsed time
// both pass its end. A forward wall step moves admission time but not
// elapsed time, so the episode holds; elapsed time alone does not end it
// either.
func TestPlaceNeedsElapsedTimeToEndAnEpisode(t *testing.T) {
	start := EpisodeClock{Now: t0, Elapsed: 10 * time.Hour}
	first, err := Place(nil, nil, KindBlockIP, t0, start, sequenceIDs(t))
	if err != nil || first.Episode.EndElapsed != start.Elapsed+EpisodeQuiet {
		t.Fatalf("first observation: %+v, %v", first.Episode, err)
	}
	cur := first.Episode.WithLine(episodeLine(t, KindBlockIP, 1, 1))
	// The wall steps two hours ahead while ten minutes elapse.
	step := EpisodeClock{Now: t0.Add(2 * time.Hour), Elapsed: start.Elapsed + 10*time.Minute}
	held, err := Place(&cur, []LineState{LineEnded}, KindBlockIP, step.Now, step, sequenceIDs(t))
	if err != nil || held.Episode.ID != cur.ID || held.Generation != 2 {
		t.Fatalf("a forward step ended the episode: %+v, %v", held, err)
	}
	if want := step.Elapsed + EpisodeQuiet; held.Episode.EndElapsed != want {
		t.Fatalf("elapsed end = %v, want %v", held.Episode.EndElapsed, want)
	}
	cur = held.Episode
	for name, at := range map[string]EpisodeClock{
		"elapsed time short": {Now: cur.End(), Elapsed: cur.EndElapsed - time.Nanosecond},
		"wall time short":    {Now: cur.End().Add(-time.Nanosecond), Elapsed: cur.EndElapsed + time.Hour},
	} {
		if p, placeErr := Place(&cur, []LineState{LineEnded}, KindBlockIP, at.Now, at, sequenceIDs(t)); placeErr != nil || p.Episode.ID != cur.ID {
			t.Errorf("%s: %+v, %v", name, p.Episode, placeErr)
		}
	}
	both := EpisodeClock{Now: cur.End(), Elapsed: cur.EndElapsed}
	next, err := Place(&cur, []LineState{LineEnded}, KindBlockIP, both.Now, both, sequenceIDs(t))
	if err != nil || next.Episode.ID == cur.ID || !next.Episode.Previous.Equal(cur.End()) || next.Episode.EndElapsed != both.Elapsed+EpisodeQuiet {
		t.Fatalf("both clocks passed: %+v, %v", next.Episode, err)
	}
}

// A join moves the quiet end's elapsed time with the last observation,
// never earlier: an observation delivered late, after a forward step,
// cannot shorten the episode, and an older one changes nothing.
func TestPlaceNeverPullsTheElapsedEndEarlier(t *testing.T) {
	start := EpisodeClock{Now: t0, Elapsed: 10 * time.Hour}
	first, err := Place(nil, nil, KindBlockIP, t0, start, sequenceIDs(t))
	if err != nil {
		t.Fatal(err)
	}
	cur := first.Episode.WithLine(episodeLine(t, KindBlockIP, 1, 1))
	for _, tc := range []struct {
		name     string
		observed time.Time
		clock    EpisodeClock
		want     time.Duration
	}{
		{"a later observation", t0.Add(30 * time.Minute), EpisodeClock{Now: t0.Add(30 * time.Minute), Elapsed: start.Elapsed + 30*time.Minute}, start.Elapsed + 90*time.Minute},
		{"a late delivery after a forward step", t0.Add(5 * time.Minute), EpisodeClock{Now: t0.Add(130 * time.Minute), Elapsed: start.Elapsed + 10*time.Minute}, start.Elapsed + 10*time.Minute + EpisodeQuiet},
		{"an older observation", t0.Add(-time.Minute), EpisodeClock{Now: t0.Add(time.Minute), Elapsed: start.Elapsed + 2*time.Hour}, start.Elapsed + EpisodeQuiet},
	} {
		p, err := Place(&cur, []LineState{LineQueued}, KindBlockIP, tc.observed, tc.clock, sequenceIDs(t))
		if err != nil || p.Episode.ID != cur.ID || p.Episode.EndElapsed != tc.want {
			t.Errorf("%s: elapsed end %v, want %v (%v)", tc.name, p.Episode.EndElapsed, tc.want, err)
		}
	}
}

// A verified block's end replaces the quiet end on both clocks: its
// elapsed end is the time left until its expiry, so the episode outlasts a
// forward step for as long as the block itself.
func TestEpisodeCloseEndsAtTheBlockOnBothClocks(t *testing.T) {
	start := EpisodeClock{Now: t0, Elapsed: 10 * time.Hour}
	first, err := Place(nil, nil, KindBlockIP, t0, start, sequenceIDs(t))
	if err != nil {
		t.Fatal(err)
	}
	cur := first.Episode.WithLine(episodeLine(t, KindBlockIP, 1, 1))
	verify := EpisodeClock{Now: t0.Add(time.Minute), Elapsed: start.Elapsed + time.Minute}
	closed, err := cur.Close(t0.Add(20*time.Minute), verify)
	if err != nil || !closed.Verified.Equal(t0.Add(20*time.Minute)) || closed.EndElapsed != start.Elapsed+20*time.Minute {
		t.Fatalf("closed %+v, %v", closed, err)
	}
	if past, err := cur.Close(t0, verify); err != nil || past.EndElapsed != verify.Elapsed {
		t.Fatalf("an end already passed: %+v, %v", past, err)
	}
	// While admission time stands still after a backward step, elapsed
	// time runs on; a join leaves the block's elapsed end where it was.
	still := EpisodeClock{Now: t0.Add(2 * time.Minute), Elapsed: verify.Elapsed + 10*time.Minute, Degraded: true}
	if p, err := Place(&closed, []LineState{LineAnswered}, KindBlockIP, still.Now, still, sequenceIDs(t)); err != nil || !p.Answered || p.Episode.EndElapsed != closed.EndElapsed {
		t.Fatalf("a join moved the verified elapsed end: %+v, %v", p.Episode, err)
	}
	step := EpisodeClock{Now: t0.Add(3 * time.Hour), Elapsed: closed.EndElapsed - time.Nanosecond}
	if p, err := Place(&closed, []LineState{LineAnswered}, KindBlockIP, step.Now, step, sequenceIDs(t)); err != nil || !p.Answered || p.Episode.ID != cur.ID || p.Episode.EndElapsed != closed.EndElapsed {
		t.Fatalf("a forward step ended the verified episode: %+v, %v", p, err)
	}
	step.Elapsed++
	if p, err := Place(&closed, []LineState{LineAnswered}, KindBlockIP, step.Now, step, sequenceIDs(t)); err != nil || p.Episode.ID == cur.ID || !p.Episode.Previous.Equal(closed.Verified) {
		t.Fatalf("after the block on both clocks: %+v, %v", p.Episode, err)
	}
	if _, err := cur.Close(t0.Add(time.Hour), EpisodeClock{}); !isReason(err, ReasonInvalid) {
		t.Fatalf("closed on an unread clock: %v", err)
	}
}

// Placement needs a clock reading, non-negative elapsed time and an
// elapsed end it can represent, whether it opens an episode or joins one
// without moving its end.
func TestPlaceRefusesAnUnusableClock(t *testing.T) {
	cur := place(t, nil, nil, KindBlockIP, t0, false).Episode.WithLine(episodeLine(t, KindBlockIP, 1, 1))
	for name, c := range map[string]EpisodeClock{
		"no reading":       {},
		"negative elapsed": {Now: t0, Elapsed: -time.Nanosecond},
	} {
		if _, err := Place(nil, nil, KindBlockIP, t0, c, sequenceIDs(t)); !isReason(err, ReasonInvalid) {
			t.Errorf("%s, opening: %v", name, err)
		}
		if _, err := Place(&cur, []LineState{LineAnswered}, KindBlockIP, t0, c, sequenceIDs(t)); !isReason(err, ReasonInvalid) {
			t.Errorf("%s, joining: %v", name, err)
		}
	}
	overflow := EpisodeClock{Now: t0, Elapsed: math.MaxInt64 - time.Minute}
	if _, err := Place(nil, nil, KindBlockIP, t0, overflow, sequenceIDs(t)); !isReason(err, ReasonInvalid) {
		t.Errorf("elapsed end overflow: %v", err)
	}
}

// Anchoring a legacy write must not change either wall frontier or a
// known elapsed end, including a verified end and an already passed end.
func TestEpisodeAnchorElapsedPreservesBoundaries(t *testing.T) {
	for _, verified := range []bool{false, true} {
		e := testEpisodeRecord(t)
		e.Verified = time.Time{}
		if verified {
			e.Verified = t0.Add(20 * time.Minute)
		}
		c := EpisodeClock{Now: t0, Elapsed: 5 * time.Hour}
		got, err := e.AnchorElapsed(c)
		want := c.Elapsed + e.End().Sub(c.Now)
		if err != nil || got.EndElapsed != want || !got.Last.Equal(e.Last) || !got.Verified.Equal(e.Verified) || !slices.Equal(got.Lines, e.Lines) {
			t.Fatalf("anchored %+v: %+v, %v", e, got, err)
		}
		later := EpisodeClock{Now: t0, Elapsed: c.Elapsed + time.Hour, Degraded: true}
		again, err := got.AnchorElapsed(later)
		if err != nil || again.EndElapsed != want {
			t.Fatalf("maintenance moved the anchor: %+v, %v", again, err)
		}
		past, err := e.AnchorElapsed(EpisodeClock{Now: e.End().Add(time.Minute), Elapsed: c.Elapsed})
		if err != nil || past.EndElapsed != c.Elapsed {
			t.Fatalf("passed end moved backwards: %+v, %v", past, err)
		}
	}
}

// Closing and anchoring reject invalid clocks and unrepresentable sums
// without changing the input, including a saturated time subtraction.
func TestEpisodeElapsedRefusesInvalidEndsAndOverflow(t *testing.T) {
	e := testEpisodeRecord(t)
	e.Verified = time.Time{}
	for name, c := range map[string]EpisodeClock{
		"missing reading":         {},
		"negative elapsed":        {Now: t0, Elapsed: -time.Nanosecond},
		"sum overflow":            {Now: t0, Elapsed: math.MaxInt64 - time.Minute},
		"unrepresentable reading": {Now: t0.AddDate(1000, 0, 0)},
	} {
		before, err := e.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		for _, call := range []func() (Episode, error){
			func() (Episode, error) { return e.Close(t0.Add(time.Hour), c) },
			func() (Episode, error) { return e.AnchorElapsed(c) },
		} {
			got, err := call()
			if !isReason(err, ReasonInvalid) {
				t.Errorf("%s: %v", name, err)
			}
			after, encodeErr := got.MarshalBinary()
			if encodeErr != nil || !bytes.Equal(before, after) {
				t.Errorf("%s changed the row: %+v, %v", name, got, encodeErr)
			}
		}
	}
	for _, end := range []time.Time{{}, t0.AddDate(1000, 0, 0)} {
		if _, err := e.Close(end, EpisodeClock{Now: t0}); !isReason(err, ReasonInvalid) {
			t.Errorf("invalid verified end %v: %v", end, err)
		}
	}
	c := EpisodeClock{Now: time.Unix(0, math.MinInt64+1)}
	if _, err := e.Close(time.Unix(0, math.MaxInt64), c); !isReason(err, ReasonInvalid) {
		t.Errorf("saturated remaining duration: %v", err)
	}
	cur := place(t, nil, nil, KindBlockIP, t0, false).Episode.WithLine(episodeLine(t, KindBlockIP, 1, 1))
	before, err := cur.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, placeErr := Place(&cur, []LineState{LineQueued}, KindBlockIP, t0.Add(time.Minute), EpisodeClock{Now: t0.Add(time.Minute), Elapsed: math.MaxInt64 - time.Minute}, sequenceIDs(t)); !isReason(placeErr, ReasonInvalid) {
		t.Errorf("join overflow: %v", placeErr)
	}
	after, err := cur.MarshalBinary()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed join changed its input")
	}
}

// An observation dated before a forward step but placed after it takes its
// quiet hour on elapsed time from the reading that places it: the wall
// cannot say how much of the gap since the observation was real. Opening
// and joining alike.
func TestPlaceAnchorsTheQuietEndOnTheProcessingReading(t *testing.T) {
	elapsed := 10 * time.Hour
	// Forty minutes of wall step, none of it elapsed.
	stepped := EpisodeClock{Now: t0.Add(40 * time.Minute), Elapsed: elapsed, Degraded: true}
	opened, err := Place(nil, nil, KindBlockIP, t0, stepped, sequenceIDs(t))
	if err != nil || opened.Episode.EndElapsed != elapsed+EpisodeQuiet {
		t.Fatalf("opened after a step: %+v, %v", opened.Episode, err)
	}
	cur := opened.Episode.WithLine(episodeLine(t, KindBlockIP, 1, 1))
	later := EpisodeClock{Now: t0.Add(61 * time.Minute), Elapsed: elapsed + 21*time.Minute}
	if p, placeErr := Place(&cur, []LineState{LineEnded}, KindBlockIP, later.Now, later, sequenceIDs(t)); placeErr != nil || p.Episode.ID != cur.ID {
		t.Fatalf("21 elapsed minutes later the episode ended: %+v, %v", p.Episode, placeErr)
	}
	// The last observation is half an hour old when a forty-minute step
	// lands and an observation from just before the step is placed.
	first, err := Place(nil, nil, KindBlockIP, t0, EpisodeClock{Now: t0, Elapsed: elapsed}, sequenceIDs(t))
	if err != nil {
		t.Fatal(err)
	}
	row := first.Episode.WithLine(episodeLine(t, KindBlockIP, 1, 1))
	step := EpisodeClock{Now: t0.Add(70 * time.Minute), Elapsed: elapsed + 30*time.Minute, Degraded: true}
	joined, err := Place(&row, []LineState{LineQueued}, KindBlockIP, t0.Add(30*time.Minute-time.Second), step, sequenceIDs(t))
	if err != nil || joined.Episode.ID != row.ID || joined.Episode.EndElapsed != step.Elapsed+EpisodeQuiet {
		t.Fatalf("joined after a step: %+v, %v", joined.Episode, err)
	}
}
