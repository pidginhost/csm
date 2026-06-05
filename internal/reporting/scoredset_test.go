package reporting

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"
)

var setTS = time.Unix(1_700_000_000, 0).UTC()

func sampleSnapshot() ScoredSnapshot {
	return ScoredSnapshot{Version: 7, Entries: []ScoredEntry{
		{IP: "203.0.113.5", Score: 80, Classes: []Class{ClassBruteforce}, LastSeen: setTS},
	}}
}

// Cross-repo golden: this JSON must equal what csm-abuse-db's publisher signs
// for the same snapshot. The identical literal is asserted in the central
// publish test; if either side's encoding drifts, one golden fails.
func TestScoredSetGoldenCanonical(t *testing.T) {
	b, ok := MarshalScoredSnapshot(sampleSnapshot())
	if !ok {
		t.Fatal("marshal failed")
	}
	const golden = `{"version":7,"entries":[{"ip":"203.0.113.5","score":80,"classes":["bruteforce"],"last_seen":"2023-11-14T22:13:20Z"}]}`
	if string(b) != golden {
		t.Fatalf("canonical scored-set drift:\n got=%s\nwant=%s", b, golden)
	}
}

func signSnap(t *testing.T, s ScoredSnapshot) (payload, sig []byte, pubHex string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	payload, ok := MarshalScoredSnapshot(s)
	if !ok {
		t.Fatal("marshal")
	}
	return payload, ed25519.Sign(priv, payload), hex.EncodeToString(pub)
}

func signRawSet(t *testing.T, payload []byte) (sig []byte, pubHex string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return ed25519.Sign(priv, payload), hex.EncodeToString(pub)
}

func signDiff(t *testing.T, d ScoredDiff) (payload, sig []byte, pubHex string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	payload, ok := MarshalScoredDiff(d)
	if !ok {
		t.Fatal("marshal diff")
	}
	return payload, ed25519.Sign(priv, payload), hex.EncodeToString(pub)
}

func openDiffForApply(t *testing.T, d ScoredDiff) VerifiedScoredDiff {
	t.Helper()
	payload, sig, pub := signDiff(t, d)
	got, err := OpenDiff(payload, sig, pub)
	if err != nil {
		t.Fatalf("open diff: %v", err)
	}
	return got
}

func TestOpenSnapshotVerifies(t *testing.T) {
	payload, sig, pub := signSnap(t, sampleSnapshot())
	got, err := OpenSnapshot(payload, sig, pub)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got.Version != 7 || len(got.Entries) != 1 || got.Entries[0].IP != "203.0.113.5" {
		t.Fatalf("decoded = %+v", got)
	}
}

func TestOpenSnapshotRejectsTamper(t *testing.T) {
	payload, sig, pub := signSnap(t, sampleSnapshot())
	bad := append([]byte(nil), payload...)
	bad[len(bad)/2] ^= 0xff
	if _, err := OpenSnapshot(bad, sig, pub); err != ErrSetSignature {
		t.Fatalf("got %v, want ErrSetSignature", err)
	}
}

func TestOpenSnapshotRejectsUnsignedInvalidJSONBeforeDecode(t *testing.T) {
	_, sig, pub := signSnap(t, sampleSnapshot())
	if _, err := OpenSnapshot([]byte("{not-json"), sig, pub); err != ErrSetSignature {
		t.Fatalf("got %v, want ErrSetSignature", err)
	}
}

func TestOpenSnapshotRejectsWrongKey(t *testing.T) {
	payload, sig, _ := signSnap(t, sampleSnapshot())
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := OpenSnapshot(payload, sig, hex.EncodeToString(otherPub)); err != ErrSetSignature {
		t.Fatalf("got %v, want ErrSetSignature", err)
	}
}

func TestOpenSnapshotRejectsMalformedEntries(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "duplicate normalized IP",
			payload: []byte(`{"version":1,"entries":[{"ip":"203.0.113.5","score":70,"classes":["bruteforce"],"last_seen":"2023-11-14T22:13:20Z"},{"ip":"::ffff:203.0.113.5","score":80,"classes":["php_relay"],"last_seen":"2023-11-14T22:13:20Z"}]}`),
		},
		{
			name:    "empty classes",
			payload: []byte(`{"version":1,"entries":[{"ip":"203.0.113.5","score":50,"classes":[],"last_seen":"2023-11-14T22:13:20Z"}]}`),
		},
		{
			name:    "out of range score",
			payload: []byte(`{"version":1,"entries":[{"ip":"203.0.113.5","score":101,"classes":["bruteforce"],"last_seen":"2023-11-14T22:13:20Z"}]}`),
		},
		{
			name:    "zero last seen",
			payload: []byte(`{"version":1,"entries":[{"ip":"203.0.113.5","score":50,"classes":["bruteforce"],"last_seen":"0001-01-01T00:00:00Z"}]}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, pub := signRawSet(t, tt.payload)
			if _, err := OpenSnapshot(tt.payload, sig, pub); err != ErrSetInvalid {
				t.Fatalf("got %v, want ErrSetInvalid", err)
			}
		})
	}
}

func TestOpenSnapshotRejectsNonCanonical(t *testing.T) {
	// Sign a payload whose entries are NOT sorted; verification passes but the
	// re-marshal canonical check must reject it.
	noncanon := []byte(`{"version":1,"entries":[{"ip":"203.0.113.9","score":10,"classes":["bruteforce"],"last_seen":"2023-11-14T22:13:20Z"},{"ip":"198.51.100.7","score":20,"classes":["php_relay"],"last_seen":"2023-11-14T22:13:20Z"}]}`)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := ed25519.Sign(priv, noncanon)
	if _, err := OpenSnapshot(noncanon, sig, hex.EncodeToString(pub)); err != ErrSetInvalid {
		t.Fatalf("got %v, want ErrSetInvalid", err)
	}
}

func TestScoredDiffGoldenCanonical(t *testing.T) {
	b, ok := MarshalScoredDiff(ScoredDiff{
		FromVersion: 1,
		ToVersion:   2,
		Added: []ScoredEntry{{
			IP:       "203.0.113.9",
			Score:    55,
			Classes:  []Class{ClassPHPRelay, ClassBruteforce},
			LastSeen: setTS,
		}},
		Removed: []string{"198.51.100.7"},
		Changed: []ScoredEntry{{
			IP:       "203.0.113.5",
			Score:    90,
			Classes:  []Class{ClassBruteforce},
			LastSeen: setTS,
		}},
	})
	if !ok {
		t.Fatal("marshal diff failed")
	}
	const golden = `{"from_version":1,"to_version":2,"added":[{"ip":"203.0.113.9","score":55,"classes":["bruteforce","php_relay"],"last_seen":"2023-11-14T22:13:20Z"}],"removed":["198.51.100.7"],"changed":[{"ip":"203.0.113.5","score":90,"classes":["bruteforce"],"last_seen":"2023-11-14T22:13:20Z"}]}`
	if string(b) != golden {
		t.Fatalf("canonical diff drift:\n got=%s\nwant=%s", b, golden)
	}
}

func TestOpenDiffVerifiesAndNormalizes(t *testing.T) {
	payload, sig, pub := signDiff(t, ScoredDiff{
		FromVersion: 1,
		ToVersion:   2,
		Added: []ScoredEntry{{
			IP:       "203.0.113.5",
			Score:    80,
			Classes:  []Class{ClassPHPRelay, ClassBruteforce},
			LastSeen: setTS,
		}},
	})
	got, err := OpenDiff(payload, sig, pub)
	if err != nil {
		t.Fatalf("open diff: %v", err)
	}
	if got.diff.Added[0].Classes[0] != ClassBruteforce || got.diff.Added[0].Classes[1] != ClassPHPRelay {
		t.Fatalf("classes not canonical: %+v", got.diff.Added[0].Classes)
	}
}

func TestOpenDiffRejectsNonCanonical(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "field order",
			payload: []byte(`{"to_version":2,"from_version":1,"added":[],"removed":[],"changed":[]}`),
		},
		{
			name:    "mapped removed IP",
			payload: []byte(`{"from_version":1,"to_version":2,"added":[],"removed":["::ffff:203.0.113.5"],"changed":[]}`),
		},
		{
			name:    "unsorted removed IPs",
			payload: []byte(`{"from_version":1,"to_version":2,"added":[],"removed":["203.0.113.9","198.51.100.7"],"changed":[]}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, pub := signRawSet(t, tt.payload)
			if _, err := OpenDiff(tt.payload, sig, pub); err != ErrSetInvalid {
				t.Fatalf("got %v, want ErrSetInvalid", err)
			}
		})
	}
}

func TestOpenDiffRejectsInvalidEntries(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "empty classes",
			payload: []byte(`{"from_version":1,"to_version":2,"added":[{"ip":"203.0.113.5","score":80,"classes":[],"last_seen":"2023-11-14T22:13:20Z"}],"removed":[],"changed":[]}`),
		},
		{
			name:    "duplicate classes",
			payload: []byte(`{"from_version":1,"to_version":2,"added":[{"ip":"203.0.113.5","score":80,"classes":["bruteforce","bruteforce"],"last_seen":"2023-11-14T22:13:20Z"}],"removed":[],"changed":[]}`),
		},
		{
			name:    "out of range score",
			payload: []byte(`{"from_version":1,"to_version":2,"added":[{"ip":"203.0.113.5","score":-1,"classes":["bruteforce"],"last_seen":"2023-11-14T22:13:20Z"}],"removed":[],"changed":[]}`),
		},
		{
			name:    "zero last seen",
			payload: []byte(`{"from_version":1,"to_version":2,"added":[{"ip":"203.0.113.5","score":80,"classes":["bruteforce"],"last_seen":"0001-01-01T00:00:00Z"}],"removed":[],"changed":[]}`),
		},
		{
			name:    "non advancing version",
			payload: []byte(`{"from_version":2,"to_version":2,"added":[],"removed":[],"changed":[]}`),
		},
		{
			name:    "removed then added",
			payload: []byte(`{"from_version":1,"to_version":2,"added":[{"ip":"203.0.113.5","score":90,"classes":["bruteforce"],"last_seen":"2023-11-14T22:13:20Z"}],"removed":["203.0.113.5"],"changed":[]}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, pub := signRawSet(t, tt.payload)
			if _, err := OpenDiff(tt.payload, sig, pub); err != ErrSetInvalid {
				t.Fatalf("got %v, want ErrSetInvalid", err)
			}
		})
	}
}

func TestApplyDiffRoundTrip(t *testing.T) {
	base := ScoredSnapshot{Version: 1, Entries: []ScoredEntry{
		{IP: "203.0.113.5", Score: 80, Classes: []Class{ClassBruteforce}, LastSeen: setTS},
		{IP: "198.51.100.7", Score: 40, Classes: []Class{ClassPHPRelay}, LastSeen: setTS},
	}}
	d := ScoredDiff{
		FromVersion: 1, ToVersion: 2,
		Added:   []ScoredEntry{{IP: "203.0.113.9", Score: 55, Classes: []Class{ClassBruteforce}, LastSeen: setTS}},
		Removed: []string{"198.51.100.7"},
		Changed: []ScoredEntry{{IP: "203.0.113.5", Score: 90, Classes: []Class{ClassBruteforce}, LastSeen: setTS}},
	}
	out, err := ApplyDiff(base, openDiffForApply(t, d))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if out.Version != 2 || len(out.Entries) != 2 {
		t.Fatalf("applied = %+v", out)
	}
	set := NewSet(out)
	if e, ok := set.Lookup("203.0.113.5"); !ok || e.Score != 90 {
		t.Fatalf("changed entry = %+v ok=%v", e, ok)
	}
	if _, ok := set.Lookup("198.51.100.7"); ok {
		t.Fatal("removed entry still present")
	}
}

func TestApplyDiffRejectsConflictingOperations(t *testing.T) {
	base := ScoredSnapshot{Version: 1, Entries: []ScoredEntry{
		{IP: "203.0.113.5", Score: 80, Classes: []Class{ClassBruteforce}, LastSeen: setTS},
	}}
	d := ScoredDiff{
		FromVersion: 1,
		ToVersion:   2,
		Added:       []ScoredEntry{{IP: "203.0.113.5", Score: 90, Classes: []Class{ClassPHPRelay}, LastSeen: setTS}},
		Removed:     []string{"203.0.113.5"},
	}
	if _, err := ApplyDiff(base, VerifiedScoredDiff{diff: d, verified: true}); err != ErrSetInvalid {
		t.Fatalf("got %v, want ErrSetInvalid", err)
	}
}

func TestApplyDiffRejectsBaseMismatches(t *testing.T) {
	base := ScoredSnapshot{Version: 1, Entries: []ScoredEntry{
		{IP: "203.0.113.5", Score: 80, Classes: []Class{ClassBruteforce}, LastSeen: setTS},
	}}
	tests := []struct {
		name string
		diff ScoredDiff
	}{
		{
			name: "added existing",
			diff: ScoredDiff{
				FromVersion: 1,
				ToVersion:   2,
				Added:       []ScoredEntry{{IP: "203.0.113.5", Score: 90, Classes: []Class{ClassPHPRelay}, LastSeen: setTS}},
			},
		},
		{
			name: "changed missing",
			diff: ScoredDiff{
				FromVersion: 1,
				ToVersion:   2,
				Changed:     []ScoredEntry{{IP: "203.0.113.9", Score: 90, Classes: []Class{ClassPHPRelay}, LastSeen: setTS}},
			},
		},
		{
			name: "removed missing",
			diff: ScoredDiff{
				FromVersion: 1,
				ToVersion:   2,
				Removed:     []string{"198.51.100.7"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ApplyDiff(base, openDiffForApply(t, tt.diff)); err != ErrSetInvalid {
				t.Fatalf("got %v, want ErrSetInvalid", err)
			}
		})
	}
}

func TestApplyDiffNormalizesBaseAndRemovalIP(t *testing.T) {
	base := ScoredSnapshot{Version: 1, Entries: []ScoredEntry{
		{IP: "::ffff:203.0.113.5", Score: 80, Classes: []Class{ClassBruteforce}, LastSeen: setTS},
	}}
	out, err := ApplyDiff(base, openDiffForApply(t, ScoredDiff{
		FromVersion: 1,
		ToVersion:   2,
		Removed:     []string{"203.0.113.5"},
	}))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if out.Version != 2 || len(out.Entries) != 0 {
		t.Fatalf("applied = %+v, want empty version 2", out)
	}
}

func TestOpenSnapshotRejectsVersionZero(t *testing.T) {
	// A wire snapshot at version 0 (the empty-cache sentinel) must be rejected
	// so a hostile endpoint cannot pin the node to perpetual cold pulls.
	payload := []byte(`{"version":0,"entries":[{"ip":"203.0.113.5","score":80,"classes":["bruteforce"],"last_seen":"2023-11-14T22:13:20Z"}]}`)
	sig, pub := signRawSet(t, payload)
	if _, err := OpenSnapshot(payload, sig, pub); err != ErrSetInvalid {
		t.Fatalf("got %v, want ErrSetInvalid for version 0", err)
	}
}

func TestApplyDiffVersionGap(t *testing.T) {
	base := ScoredSnapshot{Version: 5}
	if _, err := ApplyDiff(base, openDiffForApply(t, ScoredDiff{FromVersion: 4, ToVersion: 6})); err != ErrSetVersionGap {
		t.Fatalf("got %v, want ErrSetVersionGap", err)
	}
}

func TestApplyDiffRejectsUnverifiedDiff(t *testing.T) {
	base := ScoredSnapshot{Version: 1}
	if _, err := ApplyDiff(base, VerifiedScoredDiff{}); err != ErrSetSignature {
		t.Fatalf("got %v, want ErrSetSignature", err)
	}
}

func TestSetLookupNormalizesIPv4Mapped(t *testing.T) {
	set := NewSet(ScoredSnapshot{Version: 1, Entries: []ScoredEntry{
		{IP: "203.0.113.5", Score: 80, Classes: []Class{ClassBruteforce}, LastSeen: setTS},
	}})
	if _, ok := set.Lookup("::ffff:203.0.113.5"); !ok {
		t.Fatal("IPv4-mapped lookup missed")
	}
}

func TestSetLookupNormalizesStoredIPAndCopiesClasses(t *testing.T) {
	set := NewSet(ScoredSnapshot{Version: 1, Entries: []ScoredEntry{
		{IP: "::ffff:203.0.113.5", Score: 80, Classes: []Class{ClassBruteforce}, LastSeen: setTS},
	}})
	got, ok := set.Lookup("203.0.113.5")
	if !ok {
		t.Fatal("lookup missed normalized stored IP")
	}
	got.Classes[0] = ClassPHPRelay
	got, ok = set.Lookup("203.0.113.5")
	if !ok || got.Classes[0] != ClassBruteforce {
		t.Fatalf("lookup leaked mutable classes: %+v ok=%v", got, ok)
	}
}
