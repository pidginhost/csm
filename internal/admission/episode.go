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
	// Answered retains attempt proof after the candidate is retired.
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
	// Previous is when the episode before this one ended, zero for the
	// first. An observation older than it belongs to that episode.
	Previous time.Time
	// PriorLast is the latest observation accepted by the previous episode.
	// Work can keep it open beyond its scheduled verified boundary.
	PriorLast time.Time
	// Lines are sorted by kind, one per kind.
	Lines []EpisodeLine
}

// End is when the episode ends unless work is still queued or in flight: at
// a verified block's original expiry, otherwise an hour after the last
// accepted observation.
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
		return bad("episode has no line")
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
	e := Episode{ID: id, Last: fromNano(rec.Last), Verified: fromNano(rec.Verified), Previous: fromNano(rec.Previous), PriorLast: fromNano(rec.PriorLast)}
	for _, l := range rec.Lines {
		e.Lines = append(e.Lines, EpisodeLine{Kind: l.Kind, Generation: l.Generation, Candidate: l.Candidate, Observed: fromNano(l.Observed), Answered: l.Answered})
	}
	if again, err := e.record(); rec.V != episodeVersion || err != nil || !slices.Equal(again.Lines, rec.Lines) || again.ID != rec.ID ||
		again.Last != rec.Last || again.Verified != rec.Verified || again.Previous != rec.Previous || again.PriorLast != rec.PriorLast {
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
	// LineAnswered: the candidate ended after an attempt.
	LineAnswered
	// LineEnded: the candidate ended before any attempt; a new generation
	// may follow.
	LineEnded
)

// LineStateOf is the state of a line whose candidate is c.
func LineStateOf(c Candidate) LineState {
	switch {
	case c.State == StateQueued && c.Attempts > 0:
		return LineRetry
	case c.State == StateQueued:
		return LineQueued
	case !c.State.Terminal():
		return LineInFlight
	case c.Attempts > 0:
		return LineAnswered
	}
	return LineEnded
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
// of its lines in order (spec 5.2). The episode ends at End once no line is
// queued or in flight; a degraded clock never ends it, since wall time alone
// cannot prove a new episode. An observation older than the previous
// episode's end is refused. next names a newly opened episode.
func Place(cur *Episode, states []LineState, kind Kind, observed time.Time, degraded bool, next func() (EpisodeID, error)) (EpisodeChoice, error) {
	if !kind.Valid() {
		return EpisodeChoice{}, refuse(ReasonInvalid, "unknown response kind")
	}
	if _, ok := unixNano(observed); !ok {
		return EpisodeChoice{}, refuse(ReasonInvalid, "observation time is not representable")
	}
	if cur != nil {
		if len(states) != len(cur.Lines) {
			return EpisodeChoice{}, refuse(ReasonInvalid, "line states do not match the episode")
		}
		live := false
		for _, s := range states {
			switch s {
			case LineQueued, LineRetry, LineInFlight:
				live = true
			case LineAnswered, LineEnded:
			default:
				return EpisodeChoice{}, refuse(ReasonInvalid, "unknown line state")
			}
		}
		if observed.Before(cur.Previous) || (!cur.PriorLast.IsZero() && !observed.After(cur.PriorLast)) {
			return EpisodeChoice{}, refuse(ReasonStale, "observation belongs to an earlier episode")
		}
		if live || degraded || observed.Before(cur.End()) {
			return join(*cur, states, kind, observed)
		}
		if !observed.After(cur.Last) {
			return EpisodeChoice{}, refuse(ReasonStale, "observation was already inside the ending episode")
		}
	}
	id, err := next()
	if err != nil {
		return EpisodeChoice{}, err
	}
	e := Episode{ID: id, Last: observed}
	if cur != nil {
		e.Previous, e.PriorLast = cur.End(), cur.Last
	}
	return EpisodeChoice{Episode: e, Generation: 1}, nil
}

func join(e Episode, states []LineState, kind Kind, observed time.Time) (EpisodeChoice, error) {
	e.Lines = slices.Clone(e.Lines)
	if observed.After(e.Last) {
		e.Last = observed
	}
	p := EpisodeChoice{Episode: e, Generation: 1}
	i := slices.IndexFunc(e.Lines, func(l EpisodeLine) bool { return l.Kind == kind })
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
