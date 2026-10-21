package admission

import (
	"bytes"
	"testing"
	"time"
)

// Design C7: an observe preview carries no review or undo, so the live
// start releases its history: Released lets it be retired from any time
// at or after its end and before its review window would have ended. Its
// target stays the ordinary one. Unreleased entries keep their encoding.
func TestHistoryEntryReleased(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    HistoryEntry
		ok   bool
	}{
		{"released at its end", HistoryEntry{General: 3000, Ended: t0, Eligible: t0, Released: true}, true},
		{"released inside the review window", HistoryEntry{General: 3000, Ended: t0, Eligible: t0.Add(time.Hour), Released: true}, true},
		{"released before its end", HistoryEntry{General: 3000, Ended: t0, Eligible: t0.Add(-time.Nanosecond), Released: true}, false},
		{"released after its review window", HistoryEntry{General: 3000, Ended: t0, Eligible: t0.Add(HistoryRetention), Released: true}, false},
		{"released while live", HistoryEntry{General: 3000, Released: true}, false},
		{"released and pinned", HistoryEntry{General: 3000, Ended: t0, Pinned: true, Released: true}, false},
	} {
		err := tc.h.Validate()
		if (err == nil) != tc.ok {
			t.Errorf("%s: Validate() = %v, want ok %v", tc.name, err, tc.ok)
			continue
		}
		if !tc.ok {
			continue
		}
		data, err := tc.h.MarshalBinary()
		if err != nil || !bytes.Contains(data, []byte(`"released":true`)) {
			t.Fatalf("%s: encoded %q, %v", tc.name, data, err)
		}
		if back, err := UnmarshalHistoryEntry(data); err != nil || back != tc.h {
			t.Errorf("%s: round trip = %+v, %v", tc.name, back, err)
		}
		if !tc.h.Target().Equal(t0.Add(HistoryTarget)) {
			t.Errorf("%s: target = %v", tc.name, tc.h.Target())
		}
	}
	plain, err := HistoryEntry{General: 3000, Ended: t0, Eligible: t0.Add(HistoryRetention)}.MarshalBinary()
	if err != nil || bytes.Contains(plain, []byte("released")) {
		t.Fatalf("an unreleased entry encodes %q, %v", plain, err)
	}
	far := time.Unix(0, 1<<62)
	largest := HistoryEntry{RootMask: (1 << MaxRoots) - 1, General: MaxHistoryBytes / 2, Reserved: MaxHistoryBytes / 2, Ended: far, Eligible: far.Add(HistoryRetention - time.Nanosecond), Released: true}
	if data, err := largest.MarshalBinary(); err != nil || len(data) > MaxHistoryEntryBytes {
		t.Fatalf("largest released entry: %d bytes (bound %d), %v", len(data), MaxHistoryEntryBytes, err)
	}
}
