package admission

import (
	"bytes"
	"math"
	"reflect"
	"testing"
	"time"
)

// linkedCandidate is alice's candidate refused because a block already
// enforces its effect, linked to that block.
func linkedCandidate(t *testing.T) Candidate {
	t.Helper()
	c := queuedCandidate(t)
	c.State, c.Disposition, c.Reason, c.Transitions = StateRefused, DispositionRefused, ReasonExistingEffect, 2
	c.Link = EffectLink{Effect: "act_0123456789abcdef0123456789abcdef", ExpiresAt: t0.Add(time.Hour)}
	return c
}

// A linked refusal is a new record version; without a link a candidate
// keeps version 1 and its exact bytes, so older records decode unchanged.
func TestCandidateLinkRoundTrips(t *testing.T) {
	for name, link := range map[string]EffectLink{
		"admission action": {Effect: "act_0123456789abcdef0123456789abcdef", ExpiresAt: t0.Add(time.Hour)},
		"permanent block":  {Effect: "eff_fedcba9876543210fedcba9876543210"},
	} {
		c := linkedCandidate(t)
		c.Link = link
		data, err := c.MarshalBinary()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		back, err := UnmarshalCandidate(data)
		if err != nil || !reflect.DeepEqual(back, c) {
			t.Fatalf("%s: round trip = %+v, %v\nwant %+v", name, back, err, c)
		}
		if !bytes.HasPrefix(data, []byte(`{"v":2,`)) {
			t.Errorf("%s: linked record is not version 2: %q", name, data)
		}
	}
	c := linkedCandidate(t)
	c.Link = EffectLink{}
	data, err := c.MarshalBinary()
	if err != nil || !bytes.HasPrefix(data, []byte(`{"v":1,`)) || bytes.Contains(data, []byte(`"link"`)) {
		t.Fatalf("unlinked record = %q, %v; want version 1 without a link", data, err)
	}
}

// Only a refusal as an existing effect names the block, and only by a
// well-formed name; a stored record must agree with its version.
func TestCandidateLinkOnlyNamesAnExistingEffect(t *testing.T) {
	for name, change := range map[string]func(*Candidate){
		"another refusal":  func(c *Candidate) { c.Reason = ReasonProtected },
		"queued":           func(c *Candidate) { c.State, c.Disposition, c.Reason, c.Transitions = StateQueued, 0, 0, 1 },
		"unnamed":          func(c *Candidate) { c.Link.Effect = "" },
		"malformed":        func(c *Candidate) { c.Link.Effect = "act_0123456789ABCDEF0123456789abcdef" },
		"other prefix":     func(c *Candidate) { c.Link.Effect = "ev_0123456789abcdef0123456789abcdef" },
		"short":            func(c *Candidate) { c.Link.Effect = "eff_0123456789abcdef" },
		"before the epoch": func(c *Candidate) { c.Link.ExpiresAt = time.Unix(-1, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			c := linkedCandidate(t)
			change(&c)
			if err := c.Validate(); refusalReason(err) != ReasonInvalid {
				t.Errorf("invalid link validated: %v", err)
			}
			if _, err := c.MarshalBinary(); refusalReason(err) != ReasonInvalid {
				t.Errorf("invalid link encoded: %v", err)
			}
		})
	}
	linked, err := linkedCandidate(t).record()
	if err != nil {
		t.Fatal(err)
	}
	plain := linked
	plain.Link = nil
	for name, rec := range map[string]candidateRecord{
		"version 1 with a link":    func() candidateRecord { r := linked; r.V = 1; return r }(),
		"version 2 without a link": func() candidateRecord { r := plain; r.V = 2; return r }(),
	} {
		data, err := sealRecord(rec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := UnmarshalCandidate(data); err != ErrCorruptRecord {
			t.Errorf("%s: err = %v, want ErrCorruptRecord", name, err)
		}
	}
}

// A link is part of the bytes a candidate can hold, so storage accounting
// charges it; an unlinked candidate is charged as before.
func TestCandidateMaxBytesCountsALink(t *testing.T) {
	c := linkedCandidate(t)
	linked, err := c.MaxBytes()
	if err != nil {
		t.Fatal(err)
	}
	c.Link.ExpiresAt = time.Unix(0, math.MaxInt64)
	widest, err := c.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	c.Link = EffectLink{}
	plain, err := c.MaxBytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(widest) > linked || linked <= plain || linked > MaxCandidateBytes/2 {
		t.Fatalf("linked max %d, widest encoding %d, unlinked max %d", linked, len(widest), plain)
	}
}
