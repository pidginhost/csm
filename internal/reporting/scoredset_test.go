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

func TestOpenSnapshotRejectsWrongKey(t *testing.T) {
	payload, sig, _ := signSnap(t, sampleSnapshot())
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := OpenSnapshot(payload, sig, hex.EncodeToString(otherPub)); err != ErrSetSignature {
		t.Fatalf("got %v, want ErrSetSignature", err)
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
	out, err := ApplyDiff(base, d)
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

func TestApplyDiffVersionGap(t *testing.T) {
	base := ScoredSnapshot{Version: 5}
	if _, err := ApplyDiff(base, ScoredDiff{FromVersion: 4, ToVersion: 6}); err != ErrSetVersionGap {
		t.Fatalf("got %v, want ErrSetVersionGap", err)
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
