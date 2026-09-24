package responsereplay

import "testing"

func FuzzDecodeFinding(f *testing.F) {
	for _, seed := range []string{
		"", "{}", "[]", "null", `{"v":1}`, `{"v":1,"v":1}`, `{"V":1}`, `{"v":1}{"v":1}`, `{"v":1} x`,
		`{"v":1,"ts":"2026-09-08T10:00:00Z","check":"a"}`, `{"v":1,"ts":"0001-01-01T00:00:00Z"}`,
		`{"v":1,"ts":"2026-09-08T10:00:00Z","process":{"pid":1,"parent":{"pid":2}}}`, `{"v":1,"ts":"2026-09-08T10:00:00Z","details":null}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		finding, stamped, err := decodeFinding(data)
		if err != nil {
			return
		}
		// A row replay keeps always has a position in time.
		if stamped == finding.At.IsZero() {
			t.Fatalf("stamped=%v with time %v", stamped, finding.At)
		}
	})
}
