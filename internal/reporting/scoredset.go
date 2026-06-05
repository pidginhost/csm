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
// signed bytes. TestScoredSetGoldenCanonical pins the canonical form.

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

// VerifiedScoredDiff has passed Ed25519 verification and canonical decode.
// Its internals stay opaque so raw decoded bytes cannot be fed to ApplyDiff.
type VerifiedScoredDiff struct {
	diff     ScoredDiff
	verified bool
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

func canonicalRemovedIPs(in []string) ([]string, bool) {
	out := make([]string, len(in))
	seen := make(map[string]struct{}, len(in))
	for i, ip := range in {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return nil, false
		}
		canonical := parsed.String()
		if _, dup := seen[canonical]; dup {
			return nil, false
		}
		seen[canonical] = struct{}{}
		out[i] = canonical
	}
	sort.Strings(out)
	return out, true
}

func canonicalScoredDiff(d ScoredDiff) (ScoredDiff, bool) {
	if d.ToVersion <= d.FromVersion {
		return ScoredDiff{}, false
	}
	added, ok := canonicalScoredEntries(d.Added)
	if !ok {
		return ScoredDiff{}, false
	}
	changed, ok := canonicalScoredEntries(d.Changed)
	if !ok {
		return ScoredDiff{}, false
	}
	removed, ok := canonicalRemovedIPs(d.Removed)
	if !ok {
		return ScoredDiff{}, false
	}
	if !scoredDiffOperationsDistinct(added, changed, removed) {
		return ScoredDiff{}, false
	}
	return ScoredDiff{
		FromVersion: d.FromVersion,
		ToVersion:   d.ToVersion,
		Added:       added,
		Removed:     removed,
		Changed:     changed,
	}, true
}

func scoredDiffOperationsDistinct(added, changed []ScoredEntry, removed []string) bool {
	seen := make(map[string]struct{}, len(added)+len(changed)+len(removed))
	for _, e := range added {
		seen[e.IP] = struct{}{}
	}
	for _, e := range changed {
		if _, dup := seen[e.IP]; dup {
			return false
		}
		seen[e.IP] = struct{}{}
	}
	for _, ip := range removed {
		if _, dup := seen[ip]; dup {
			return false
		}
		seen[ip] = struct{}{}
	}
	return true
}

func validateDiffAgainstBase(base ScoredSnapshot, d ScoredDiff) bool {
	m := indexScoredEntries(base.Entries)
	for _, ip := range d.Removed {
		if _, ok := m[ip]; !ok {
			return false
		}
	}
	for _, e := range d.Added {
		if _, ok := m[e.IP]; ok {
			return false
		}
	}
	for _, e := range d.Changed {
		if _, ok := m[e.IP]; !ok {
			return false
		}
	}
	return true
}

func indexScoredEntries(entries []ScoredEntry) map[string]ScoredEntry {
	m := make(map[string]ScoredEntry, len(entries))
	for _, e := range entries {
		m[e.IP] = e
	}
	return m
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

// MarshalScoredDiff deterministically encodes d (for signature/re-marshal).
func MarshalScoredDiff(d ScoredDiff) ([]byte, bool) {
	d, ok := canonicalScoredDiff(d)
	if !ok {
		return nil, false
	}
	b, err := json.Marshal(d)
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
func OpenDiff(payload, sig []byte, pubHex string) (VerifiedScoredDiff, error) {
	if err := VerifyScoredSet(payload, sig, pubHex); err != nil {
		return VerifiedScoredDiff{}, err
	}
	var d ScoredDiff
	if err := decodeStrict(payload, &d); err != nil {
		return VerifiedScoredDiff{}, ErrSetInvalid
	}
	d, ok := canonicalScoredDiff(d)
	if !ok {
		return VerifiedScoredDiff{}, ErrSetInvalid
	}
	canon, ok := MarshalScoredDiff(d)
	if !ok || !bytes.Equal(canon, payload) {
		return VerifiedScoredDiff{}, ErrSetInvalid
	}
	return VerifiedScoredDiff{diff: d, verified: true}, nil
}

// ApplyDiff applies a verified diff onto base, returning the resulting snapshot.
func ApplyDiff(base ScoredSnapshot, d VerifiedScoredDiff) (ScoredSnapshot, error) {
	if !d.verified {
		return ScoredSnapshot{}, ErrSetSignature
	}
	entries, ok := canonicalScoredEntries(base.Entries)
	if !ok {
		return ScoredSnapshot{}, ErrSetInvalid
	}
	base.Entries = entries
	diff := d.diff
	if diff.FromVersion != base.Version {
		return ScoredSnapshot{}, ErrSetVersionGap
	}
	if !validateDiffAgainstBase(base, diff) {
		return ScoredSnapshot{}, ErrSetInvalid
	}
	m := indexScoredEntries(base.Entries)
	for _, ip := range diff.Removed {
		delete(m, ip)
	}
	for _, e := range diff.Added {
		m[e.IP] = e
	}
	for _, e := range diff.Changed {
		m[e.IP] = e
	}
	out := make([]ScoredEntry, 0, len(m))
	for _, e := range m {
		out = append(out, e)
	}
	entries, ok = canonicalScoredEntries(out)
	if !ok {
		return ScoredSnapshot{}, ErrSetInvalid
	}
	return ScoredSnapshot{Version: diff.ToVersion, Entries: entries}, nil
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
		if ce, ok := canonicalScoredEntry(e); ok {
			e = ce
		}
		e.Classes = append([]Class(nil), e.Classes...)
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
	if ok {
		e.Classes = append([]Class(nil), e.Classes...)
	}
	return e, ok
}

// Len returns the number of scored IPs.
func (s *Set) Len() int { return len(s.byIP) }
