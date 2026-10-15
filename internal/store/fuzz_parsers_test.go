package store

import (
	"testing"
	"time"
)

// Example keys and values come from this build, older builds and the
// legacy writer. Maintenance parses them and must never panic: a key time it
// accepts orders exactly against a cutoff, and a session it reads is the
// record's own.
func FuzzDryRunExampleRecord(f *testing.F) {
	f.Add([]byte("2026-10-15T12:00:00.000000000Z:192.0.2.1:cand_00000000000000000000000000000001"), []byte(`{"session_id":"0123456789abcdef0123456789abcdef"}`))
	f.Add([]byte("2026-10-15T12:00:00.5Z:2001:db8::1"), []byte(`{"ip":"2001:db8::1","reason":"x","timeout_sec":1}`))
	f.Add([]byte("Z:"), []byte("not json"))
	f.Add([]byte("2026-13-40T99:00:00Z:192.0.2.1"), []byte(`{"session_id":7}`))
	f.Fuzz(func(t *testing.T, key, value []byte) {
		if at, ok := dryRunKeyAt(string(key)); ok {
			if dryRunKeyBefore(key, at) || !dryRunKeyBefore(key, at.Add(time.Nanosecond)) {
				t.Fatalf("key %q parsed as %v but does not order against it", key, at)
			}
		} else if dryRunKeyBefore(key, time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)) {
			t.Fatalf("an unparsed key %q was judged old", key)
		}
		_ = dryRunSession(value)
	})
}
