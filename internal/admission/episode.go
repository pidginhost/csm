package admission

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math"
	"slices"
	"time"
)

// EpisodeQuiet is how long an episode without a verified response lasts
// after its last accepted observation (spec 5.2).
const EpisodeQuiet = time.Hour

// Episode row bounds. The widest key is a service target's; the record
// holds at most one line per kind.
const (
	MaxEpisodeKeyBytes = 64
	MaxEpisodeBytes    = 1024
)

const (
	episodeVersion         = 1
	episodeSequenceVersion = 1
)

// EpisodeLine is the latest generation one kind queued in an episode.
type EpisodeLine struct {
	Kind       Kind
	Generation uint32
	Candidate  CandidateID
	// Observed is the latest qualifying observation of this kind. A new
	// generation needs later evidence; a repeated root cannot reset age.
	Observed time.Time
	// Answered retains, after the candidate is retired, that its verified
	// effect or observe preview answers the kind for the rest of the
	// episode.
	Answered bool
}

// Episode is the engine's record of the current offense episode at one
// target: its identity, the observations and response that bound it, and
// the latest candidate of each kind (spec 5.2). Responses of different
// kinds at one target share the episode.
type Episode struct {
	ID EpisodeID
	// Last is the latest accepted observation.
	Last time.Time
	// Verified is the original expiry of the episode's verified block,
	// zero until one.
	Verified time.Time
	// EndElapsed is the ceiling's elapsed time at which End passes on
	// elapsed time too. Zero for a row written before elapsed ends, which
	// ends on wall time alone.
	EndElapsed time.Duration
	// Previous is when the episode before this one ended, zero for the
	// first. An observation older than it belongs to that episode.
	Previous time.Time
	// PriorLast is the latest observation accepted by the previous episode.
	// An unresolved line or a degraded clock can keep it open beyond its
	// scheduled verified boundary.
	PriorLast time.Time
	// Lines are sorted by kind, one per kind.
	Lines []EpisodeLine
}

// End is when the episode ends on the wall: at a verified block's original
// expiry, whatever other kinds have queued or in flight, otherwise an hour
// after the last accepted observation once no work is queued or in flight.
// It ends only once EndElapsed has passed as well. An unresolved line or a
// degraded clock keeps it open either way.
func (e Episode) End() time.Time {
	if !e.Verified.IsZero() {
		return e.Verified
	}
	return e.Last.Add(EpisodeQuiet)
}

// Line is the line of kind.
func (e Episode) Line(kind Kind) (EpisodeLine, bool) {
	i := slices.IndexFunc(e.Lines, func(l EpisodeLine) bool { return l.Kind == kind })
	if i < 0 {
		return EpisodeLine{}, false
	}
	return e.Lines[i], true
}

// WithLine returns e with l as the line of its kind.
func (e Episode) WithLine(l EpisodeLine) Episode {
	lines := slices.DeleteFunc(slices.Clone(e.Lines), func(have EpisodeLine) bool { return have.Kind == l.Kind })
	i, _ := slices.BinarySearchFunc(lines, l.Kind, func(have EpisodeLine, k Kind) int { return int(have.Kind) - int(k) })
	e.Lines = slices.Insert(lines, i, l)
	return e
}

// WithoutCandidate clears a deleted candidate but retains its generation
// and observation frontier while another candidate keeps the row alive.
func (e Episode) WithoutCandidate(id CandidateID, answered bool) (Episode, bool) {
	if id == "" {
		return e, false
	}
	i := slices.IndexFunc(e.Lines, func(l EpisodeLine) bool { return l.Candidate == id })
	if i < 0 {
		return e, false
	}
	e.Lines = slices.Clone(e.Lines)
	e.Lines[i].Candidate, e.Lines[i].Answered = "", answered
	return e, true
}

// HasCandidates says whether a stored candidate still anchors this row.
func (e Episode) HasCandidates() bool {
	return slices.ContainsFunc(e.Lines, func(l EpisodeLine) bool { return l.Candidate != "" })
}

type episodeLineRecord struct {
	Kind       Kind        `json:"kind"`
	Generation uint32      `json:"generation"`
	Candidate  CandidateID `json:"candidate,omitempty"`
	Observed   int64       `json:"observed"`
	Answered   bool        `json:"answered,omitempty"`
}

type episodeRecord struct {
	V         uint8               `json:"v"`
	ID        string              `json:"id"`
	Last      int64               `json:"last"`
	Verified  int64               `json:"verified,omitempty"`
	Elapsed   int64               `json:"end_elapsed,omitempty"`
	Previous  int64               `json:"previous,omitempty"`
	PriorLast int64               `json:"prior_last,omitempty"`
	Lines     []episodeLineRecord `json:"lines"`
}

func (e Episode) record() (episodeRecord, error) {
	bad := func(detail string) (episodeRecord, error) {
		return episodeRecord{}, refuse(ReasonInvalid, detail)
	}
	if e.ID.IsZero() {
		return bad("episode has no ID")
	}
	rec := episodeRecord{V: episodeVersion, ID: e.ID.String()}
	var ok bool
	if rec.Last, ok = unixNano(e.Last); !ok {
		return bad("episode has no representable last observation")
	}
	if !e.Verified.IsZero() {
		if rec.Verified, ok = unixNano(e.Verified); !ok {
			return bad("episode expiry is not representable")
		}
	}
	if e.EndElapsed < 0 {
		return bad("episode elapsed end is negative")
	}
	rec.Elapsed = int64(e.EndElapsed)
	if !e.Previous.IsZero() {
		if rec.Previous, ok = unixNano(e.Previous); !ok || e.Previous.After(e.Last) {
			return bad("previous episode ends after this one's last observation")
		}
	}
	if !e.PriorLast.IsZero() {
		if rec.PriorLast, ok = unixNano(e.PriorLast); !ok || !e.PriorLast.Before(e.Last) {
			return bad("previous observations overlap this episode")
		}
	}
	if !e.HasCandidates() {
		line, found := e.Line(KindBlockIP)
		if e.Verified.IsZero() || e.EndElapsed <= 0 || !found || !line.Answered {
			return bad("episode has no retained candidate or verified block frontier")
		}
	}
	for i, l := range e.Lines {
		switch _, err := ParseCandidateID(string(l.Candidate)); {
		case !l.Kind.Valid() || l.Generation == 0 || (l.Candidate != "" && err != nil) || (l.Candidate != "" && l.Answered):
			return bad("episode line is malformed")
		case i > 0 && l.Kind <= e.Lines[i-1].Kind:
			return bad("episode lines are not one per kind in kind order")
		}
		observed, ok := unixNano(l.Observed)
		if !ok || l.Observed.After(e.Last) {
			return bad("episode line has no valid observation frontier")
		}
		rec.Lines = append(rec.Lines, episodeLineRecord{Kind: l.Kind, Generation: l.Generation, Candidate: l.Candidate, Observed: observed, Answered: l.Answered})
	}
	return rec, nil
}

func (e Episode) MarshalBinary() ([]byte, error) {
	rec, err := e.record()
	if err != nil {
		return nil, err
	}
	return sealRecord(rec)
}

// UnmarshalEpisode decodes a stored episode and checks its invariants.
func UnmarshalEpisode(data []byte) (Episode, error) {
	var rec episodeRecord
	if err := openRecord(data, &rec); err != nil {
		return Episode{}, err
	}
	id, err := ParseEpisodeID(rec.ID)
	if err != nil {
		return Episode{}, ErrCorruptRecord
	}
	e := Episode{ID: id, Last: fromNano(rec.Last), Verified: fromNano(rec.Verified), EndElapsed: time.Duration(rec.Elapsed), Previous: fromNano(rec.Previous), PriorLast: fromNano(rec.PriorLast)}
	for _, l := range rec.Lines {
		e.Lines = append(e.Lines, EpisodeLine{Kind: l.Kind, Generation: l.Generation, Candidate: l.Candidate, Observed: fromNano(l.Observed), Answered: l.Answered})
	}
	if again, err := e.record(); rec.V != episodeVersion || err != nil || !slices.Equal(again.Lines, rec.Lines) || again.ID != rec.ID ||
		again.Last != rec.Last || again.Verified != rec.Verified || again.Elapsed != rec.Elapsed || again.Previous != rec.Previous || again.PriorLast != rec.PriorLast {
		return Episode{}, ErrCorruptRecord
	}
	return e, nil
}

// LineState is what a line's candidate lets a new observation of its kind
// do.
type LineState uint8

const (
	// LineQueued: the candidate waits; the observation coalesces into it.
	LineQueued LineState = iota + 1
	// LineRetry: the candidate is queued after an attempt; it stays live
	// but accepts no further observations into the retry.
	LineRetry
	// LineInFlight: an attempt is reserved or running.
	LineInFlight
	// LineAnswered: the candidate's effect was verified or previewed; it
	// answers the kind for the rest of the episode.
	LineAnswered
	// LineEnded: the candidate ended without an effect that answers the
	// kind: before any attempt, after its last attempt failed, or after
	// recovery retired its unknown outcome. A new generation may follow.
	LineEnded
	// LineUnresolved: the candidate's attempt ended unknown and recovery
	// has not retired it. It answers the kind but never extends the
	// episode, and it holds the episode open until it is retired. The ledger
	// separately holds other kinds on the same target before execution.
	LineUnresolved
)

// LineStateOf is the state of a line whose candidate is c; retired says
// whether recovery retired c's unknown outcome.
func LineStateOf(c Candidate, retired bool) LineState {
	switch {
	case c.State == StateQueued && c.Attempts > 0:
		return LineRetry
	case c.State == StateQueued:
		return LineQueued
	case !c.State.Terminal():
		return LineInFlight
	case c.State == StateUnknown && !retired:
		return LineUnresolved
	case c.State == StateVerified || c.State == StateObserved:
		return LineAnswered
	}
	return LineEnded
}

// EpisodeClock is the reading episode boundaries are judged on.
type EpisodeClock struct {
	// Now is admission time.
	Now time.Time
	// Elapsed is the ceiling's elapsed time at Now, credited within a boot
	// only, so neither a wall step nor downtime advances it.
	Elapsed time.Duration
	// Degraded is set when the reading was degraded: wall time alone
	// proves nothing new then.
	Degraded bool
}

func (c EpisodeClock) check() error {
	_, ok := unixNano(c.Now)
	switch {
	case !ok:
		return refuse(ReasonInvalid, "episode clock has no representable reading")
	case c.Elapsed < 0:
		return refuse(ReasonInvalid, "episode clock has negative elapsed time")
	}
	return nil
}

// elapsedEnd is the elapsed time at which end passes, read on c: the time
// left until end added to c.Elapsed.
func elapsedEnd(end time.Time, c EpisodeClock) (time.Duration, error) {
	left := max(end.Sub(c.Now), 0)
	if left > 0 && !c.Now.Add(left).Equal(end) {
		return 0, refuse(ReasonInvalid, "episode remaining duration is not representable")
	}
	if left > math.MaxInt64-c.Elapsed {
		return 0, refuse(ReasonInvalid, "episode end is not representable in elapsed time")
	}
	return c.Elapsed + left, nil
}

// quietElapsedEnd is the elapsed end of a quiet hour that starts at the
// reading c. An observation's age is wall time, which a forward step
// inflates, so the hour runs on elapsed time from the placing reading; an
// observation processed late can lengthen its episode, never shorten it.
func quietElapsedEnd(c EpisodeClock) (time.Duration, error) {
	return elapsedEnd(c.Now.Add(EpisodeQuiet), c)
}

// AnchorElapsed gives a legacy row its remaining elapsed duration on
// its next write. Existing anchors survive maintenance without moving.
func (e Episode) AnchorElapsed(c EpisodeClock) (Episode, error) {
	if err := c.check(); err != nil {
		return e, err
	}
	if e.EndElapsed != 0 {
		return e, nil
	}
	end, err := elapsedEnd(e.End(), c)
	if err != nil {
		return e, err
	}
	e.EndElapsed = end
	return e, nil
}

// Close ends e at verified, its verified block's original expiry in
// admission time, read on c: the elapsed end becomes the time left until
// then, so the episode lasts as long as the block on both clocks. An
// episode already verified keeps its scheduled boundary (spec 5.2): a
// same-episode re-admission's block never moves it.
func (e Episode) Close(verified time.Time, c EpisodeClock) (Episode, error) {
	if _, ok := unixNano(verified); !ok {
		return e, refuse(ReasonInvalid, "episode expiry is not representable")
	}
	if err := c.check(); err != nil {
		return e, err
	}
	if !e.Verified.IsZero() {
		return e.AnchorElapsed(c)
	}
	at, err := elapsedEnd(verified, c)
	if err != nil {
		return e, err
	}
	e.Verified, e.EndElapsed = verified, at
	return e, nil
}

// EpisodeChoice is where one observation belongs.
type EpisodeChoice struct {
	// Episode is the record after accepting the observation. A newly opened
	// one has no lines yet.
	Episode Episode
	// Generation is the generation of its kind the observation joins.
	Generation uint32
	// Answered is set when that kind's line already has an attempt: the
	// observation extends the episode but queues nothing.
	Answered bool
}

// Place decides where an observation of kind made at observed belongs,
// given the target's current episode (nil for none) and the state of each
// of its lines in order, read on clock (spec 5.2). The episode ends at End:
// at a verified block's expiry even while other kinds' work is queued or in
// flight (I1), otherwise once no line is queued or in flight. It ends only
// once clock's elapsed time has passed EndElapsed too, so a forward wall
// step cannot end it early and downtime grants it no time (I3). An
// unresolved line holds it open, and a degraded clock never ends it, since
// wall time alone cannot prove a new episode. An observation older than the
// previous episode's end is refused. next names a newly opened episode.
func Place(cur *Episode, states []LineState, kind Kind, observed time.Time, clock EpisodeClock, next func() (EpisodeID, error)) (EpisodeChoice, error) {
	if !kind.Valid() {
		return EpisodeChoice{}, refuse(ReasonInvalid, "unknown response kind")
	}
	if _, ok := unixNano(observed); !ok {
		return EpisodeChoice{}, refuse(ReasonInvalid, "observation time is not representable")
	}
	if err := clock.check(); err != nil {
		return EpisodeChoice{}, err
	}
	if cur != nil {
		if len(states) != len(cur.Lines) {
			return EpisodeChoice{}, refuse(ReasonInvalid, "line states do not match the episode")
		}
		live, unresolved := false, false
		for _, s := range states {
			switch s {
			case LineQueued, LineRetry, LineInFlight:
				live = true
			case LineUnresolved:
				unresolved = true
			case LineAnswered, LineEnded:
			default:
				return EpisodeChoice{}, refuse(ReasonInvalid, "unknown line state")
			}
		}
		if observed.Before(cur.Previous) || (!cur.PriorLast.IsZero() && !observed.After(cur.PriorLast)) {
			return EpisodeChoice{}, refuse(ReasonStale, "observation belongs to an earlier episode")
		}
		due := !observed.Before(cur.End()) && clock.Elapsed >= cur.EndElapsed
		// A verified block's expiry ends the episode whatever else is
		// queued (I1); only its own kind could hold it, and that line is
		// the verified one.
		if !cur.Verified.IsZero() && due {
			live = false
		}
		if live || unresolved || clock.Degraded || !due {
			return join(*cur, states, kind, observed, clock)
		}
		if !observed.After(cur.Last) {
			return EpisodeChoice{}, refuse(ReasonStale, "observation was already inside the ending episode")
		}
	}
	end, err := quietElapsedEnd(clock)
	if err != nil {
		return EpisodeChoice{}, err
	}
	id, err := next()
	if err != nil {
		return EpisodeChoice{}, err
	}
	e := Episode{ID: id, Last: observed, EndElapsed: end}
	if cur != nil {
		e.Previous, e.PriorLast = cur.End(), cur.Last
	}
	return EpisodeChoice{Episode: e, Generation: 1}, nil
}

func join(e Episode, states []LineState, kind Kind, observed time.Time, clock EpisodeClock) (EpisodeChoice, error) {
	e.Lines = slices.Clone(e.Lines)
	i := slices.IndexFunc(e.Lines, func(l EpisodeLine) bool { return l.Kind == kind })
	// An unresolved line answers without extending the episode or its own
	// frontier: an attack that outlasts the uncertainty is not stretched
	// into it (I2).
	if i >= 0 && states[i] == LineUnresolved {
		return EpisodeChoice{Episode: e, Generation: e.Lines[i].Generation, Answered: true}, nil
	}
	if observed.After(e.Last) {
		e.Last = observed
		// The quiet end moves with the last observation; its elapsed end
		// never moves earlier, so an observation delivered late after a
		// forward step cannot shorten the episode. A verified end stays.
		if e.Verified.IsZero() {
			end, err := quietElapsedEnd(clock)
			if err != nil {
				return EpisodeChoice{}, err
			}
			e.EndElapsed = max(e.EndElapsed, end)
		}
	}
	p := EpisodeChoice{Episode: e, Generation: 1}
	if i < 0 {
		return p, nil
	}
	p.Generation = e.Lines[i].Generation
	switch states[i] {
	case LineRetry, LineInFlight, LineAnswered:
		p.Answered = true
	case LineEnded:
		if p.Generation == math.MaxUint32 {
			return EpisodeChoice{}, refuse(ReasonInvalid, "episode has no generation left")
		}
		if !observed.After(e.Lines[i].Observed) {
			return EpisodeChoice{}, refuse(ReasonStale, "an ended generation needs a later qualifying observation")
		}
		p.Generation++
	}
	if observed.After(p.Episode.Lines[i].Observed) {
		p.Episode.Lines[i].Observed = observed
	}
	return p, nil
}

// EpisodeSequence names episodes: a random nonce chosen when the ledger is
// created, and a counter. IDs never repeat within a ledger, nor across a
// ledger created again after loss, whose earlier action IDs the action log
// still holds.
type EpisodeSequence struct {
	Nonce [16]byte
	// Next is the sequence number the next episode takes.
	Next uint64
}

// NewEpisodeSequence starts a sequence with a nonce read from r.
func NewEpisodeSequence(r io.Reader) (EpisodeSequence, error) {
	var s EpisodeSequence
	if _, err := io.ReadFull(r, s.Nonce[:]); err != nil {
		return EpisodeSequence{}, err
	}
	return s, nil
}

// Take names the next episode.
func (s *EpisodeSequence) Take() (EpisodeID, error) {
	if s.Next == math.MaxUint64 {
		return EpisodeID{}, refuse(ReasonInvalid, "episode sequence is exhausted")
	}
	h := sha256.New()
	writeField(h, []byte{identityVersion})
	writeField(h, []byte("episode"))
	writeField(h, s.Nonce[:])
	writeField(h, binary.BigEndian.AppendUint64(nil, s.Next))
	var id EpisodeID
	copy(id[:], h.Sum(nil))
	if id.IsZero() {
		return EpisodeID{}, ErrCorruptRecord
	}
	s.Next++
	return id, nil
}

type episodeSequenceRecord struct {
	V     uint8  `json:"v"`
	Nonce string `json:"nonce"`
	Next  uint64 `json:"next"`
}

func (s EpisodeSequence) MarshalBinary() ([]byte, error) {
	if s.Nonce == ([16]byte{}) {
		return nil, refuse(ReasonInvalid, "episode sequence has no nonce")
	}
	return sealRecord(episodeSequenceRecord{V: episodeSequenceVersion, Nonce: hex.EncodeToString(s.Nonce[:]), Next: s.Next})
}

// UnmarshalEpisodeSequence decodes a stored episode sequence.
func UnmarshalEpisodeSequence(data []byte) (EpisodeSequence, error) {
	var rec episodeSequenceRecord
	if err := openRecord(data, &rec); err != nil {
		return EpisodeSequence{}, err
	}
	var s EpisodeSequence
	if rec.V != episodeSequenceVersion || !lowerHex(rec.Nonce, 32) {
		return EpisodeSequence{}, ErrCorruptRecord
	}
	_, _ = hex.Decode(s.Nonce[:], []byte(rec.Nonce))
	if s.Nonce == ([16]byte{}) {
		return EpisodeSequence{}, ErrCorruptRecord
	}
	s.Next = rec.Next
	return s, nil
}
