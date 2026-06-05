package reporting

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sort"
	"time"
)

// This is the node consume side of the signed scored-set. The encoding here
// MUST stay byte-identical to the central publisher (csm-abuse-db
// internal/publish) so a node re-marshals a decoded payload to exactly the
// signed bytes. TestScoredSetGolden pins the canonical form.

var (
	// ErrSetSignature means the scored-set signature did not verify.
	ErrSetSignature = errors.New("reporting: scored-set signature invalid")
	// ErrSetInvalid means a decoded scored-set was malformed or noncanonical.
	ErrSetInvalid = errors.New("reporting: scored-set invalid")
	// ErrSetVersionGap means a diff does not apply onto the cached version.
	ErrSetVersionGap = errors.New("reporting: scored-set version gap")
)

// ScoredEntry is one scored IP in the distributed set.
type ScoredEntry struct {
	IP       string    `json:"ip"`
	Score    int       `json:"score"`
	Classes  []Class   `json:"classes"`
	LastSeen time.Time `json:"last_seen"`
}

// ScoredSnapshot is the full scored-set at a version.
type ScoredSnapshot struct {
	Version uint64        `json:"version"`
	Entries []ScoredEntry `json:"entries"`
}

// ScoredDiff is an incremental update from FromVersion to ToVersion.
type ScoredDiff struct {
	FromVersion uint64        `json:"from_version"`
	ToVersion   uint64        `json:"to_version"`
	Added       []ScoredEntry `json:"added"`
	Removed     []string      `json:"removed"`
	Changed     []ScoredEntry `json:"changed"`
}

func validScoredEntry(e ScoredEntry) bool {
	if net.ParseIP(e.IP) == nil || e.Score < 0 || e.Score > 100 || e.LastSeen.IsZero() {
		return false
	}
	for _, c := range e.Classes {
		if !knownClass(c) {
			return false
		}
	}
	return true
}

func knownClass(c Class) bool {
	switch c {
	case ClassBruteforce, ClassPHPRelay, ClassCredentialStuffing, ClassBadASNEgress:
		return true
	}
	return false
}

func canonicalScoredClasses(in []Class) ([]Class, bool) {
	if len(in) == 0 {
		return nil, false
	}
	out := append([]Class(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	for i, c := range out {
		if !knownClass(c) {
			return nil, false
		}
		if i > 0 && c == out[i-1] {
			return nil, false
		}
	}
	return out, true
}

func canonicalScoredEntry(e ScoredEntry) (ScoredEntry, bool) {
	ip := net.ParseIP(e.IP)
	if ip == nil || e.Score < 0 || e.Score > 100 || e.LastSeen.IsZero() {
		return ScoredEntry{}, false
	}
	classes, ok := canonicalScoredClasses(e.Classes)
	if !ok {
		return ScoredEntry{}, false
	}
	return ScoredEntry{IP: ip.String(), Score: e.Score, Classes: classes, LastSeen: e.LastSeen.UTC()}, true
}

func canonicalScoredEntries(in []ScoredEntry) ([]ScoredEntry, bool) {
	out := make([]ScoredEntry, len(in))
	seen := make(map[string]struct{}, len(in))
	for i, e := range in {
		ce, ok := canonicalScoredEntry(e)
		if !ok {
			return nil, false
		}
		if _, dup := seen[ce.IP]; dup {
			return nil, false
		}
		seen[ce.IP] = struct{}{}
		out[i] = ce
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out, true
}

// MarshalScoredSnapshot deterministically encodes s (for signature/re-marshal).
func MarshalScoredSnapshot(s ScoredSnapshot) ([]byte, bool) {
	entries, ok := canonicalScoredEntries(s.Entries)
	if !ok {
		return nil, false
	}
	b, err := json.Marshal(ScoredSnapshot{Version: s.Version, Entries: entries})
	if err != nil {
		return nil, false
	}
	return b, true
}

// VerifyScoredSet checks sig over payload under pubHex (the central public key).
func VerifyScoredSet(payload, sig []byte, pubHex string) error {
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return ErrSetSignature
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return ErrSetSignature
	}
	return nil
}

func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return ErrSetInvalid
		}
		return err
	}
	return nil
}

// OpenSnapshot verifies sig over payload, then decodes and canonical-checks the
// snapshot. Verification happens before any structural trust is placed in the
// bytes.
func OpenSnapshot(payload, sig []byte, pubHex string) (ScoredSnapshot, error) {
	if err := VerifyScoredSet(payload, sig, pubHex); err != nil {
		return ScoredSnapshot{}, err
	}
	var s ScoredSnapshot
	if err := decodeStrict(payload, &s); err != nil {
		return ScoredSnapshot{}, ErrSetInvalid
	}
	entries, ok := canonicalScoredEntries(s.Entries)
	if !ok {
		return ScoredSnapshot{}, ErrSetInvalid
	}
	s.Entries = entries
	canon, ok := MarshalScoredSnapshot(s)
	if !ok || !bytes.Equal(canon, payload) {
		return ScoredSnapshot{}, ErrSetInvalid
	}
	return s, nil
}

// OpenDiff verifies sig over payload then decodes the diff.
func OpenDiff(payload, sig []byte, pubHex string) (ScoredDiff, error) {
	if err := VerifyScoredSet(payload, sig, pubHex); err != nil {
		return ScoredDiff{}, err
	}
	var d ScoredDiff
	if err := decodeStrict(payload, &d); err != nil {
		return ScoredDiff{}, ErrSetInvalid
	}
	if d.ToVersion <= d.FromVersion {
		return ScoredDiff{}, ErrSetInvalid
	}
	for _, e := range append(append([]ScoredEntry(nil), d.Added...), d.Changed...) {
		if !validScoredEntry(e) {
			return ScoredDiff{}, ErrSetInvalid
		}
	}
	for _, ip := range d.Removed {
		if net.ParseIP(ip) == nil {
			return ScoredDiff{}, ErrSetInvalid
		}
	}
	return d, nil
}

// ApplyDiff applies a verified diff onto base, returning the resulting snapshot.
func ApplyDiff(base ScoredSnapshot, d ScoredDiff) (ScoredSnapshot, error) {
	if d.FromVersion != base.Version {
		return ScoredSnapshot{}, ErrSetVersionGap
	}
	m := make(map[string]ScoredEntry, len(base.Entries))
	for _, e := range base.Entries {
		m[e.IP] = e
	}
	for _, ip := range d.Removed {
		if p := net.ParseIP(ip); p != nil {
			delete(m, p.String())
		}
	}
	for _, e := range append(append([]ScoredEntry(nil), d.Added...), d.Changed...) {
		if ce, ok := canonicalScoredEntry(e); ok {
			m[ce.IP] = ce
		}
	}
	out := make([]ScoredEntry, 0, len(m))
	for _, e := range m {
		out = append(out, e)
	}
	entries, _ := canonicalScoredEntries(out)
	return ScoredSnapshot{Version: d.ToVersion, Entries: entries}, nil
}

// Set is an in-memory lookup over the current scored-set.
type Set struct {
	version uint64
	byIP    map[string]ScoredEntry
}

// NewSet builds a lookup set from a snapshot.
func NewSet(s ScoredSnapshot) *Set {
	m := make(map[string]ScoredEntry, len(s.Entries))
	for _, e := range s.Entries {
		m[e.IP] = e
	}
	return &Set{version: s.Version, byIP: m}
}

// Version returns the set's version.
func (s *Set) Version() uint64 { return s.version }

// Lookup returns the scored entry for ip, normalizing the textual form.
func (s *Set) Lookup(ip string) (ScoredEntry, bool) {
	p := net.ParseIP(ip)
	if p == nil {
		return ScoredEntry{}, false
	}
	e, ok := s.byIP[p.String()]
	return e, ok
}

// Len returns the number of scored IPs.
func (s *Set) Len() int { return len(s.byIP) }
