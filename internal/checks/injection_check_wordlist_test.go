package checks

import (
	"context"
	"testing"
)

// withWeakPasswords seeds the cached weak-password list. We fire the
// package's sync.Once with a no-op so loadWeakPasswords skips its disk
// read and returns whatever we set in `weakPasswords`. The Once stays
// fired for the rest of the test binary's lifetime, which is fine —
// every test that depends on the list seeds it explicitly via this helper.
func withWeakPasswords(t *testing.T, words []string) {
	t.Helper()
	prevWords := weakPasswords
	weakPasswords = words
	weakPasswordOnce.Do(func() {})
	t.Cleanup(func() { weakPasswords = prevWords })
}

func TestEmailPasswordWordlist(t *testing.T) {
	for _, tc := range []struct {
		name  string
		words []string
		want  string
	}{
		{"mismatch", []string{"password", "letmein", "qwerty"}, ""},
		{"match", []string{"wrongpw", "matchme", "thirdpw"}, "matchme"},
		{"empty", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withWeakPasswords(t, tc.words)
			v := mustEmailPasswordVerifier(t, "{PLAIN}matchme")
			got, err := v.firstMatch(context.Background(), loadWeakPasswords())
			if err != nil || got != tc.want {
				t.Fatalf("match = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}
