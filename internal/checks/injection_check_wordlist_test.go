package checks

import (
	"errors"
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

func TestCheckWordlistAllPasswordsRejectReturnsEmpty(t *testing.T) {
	withWeakPasswords(t, []string{"password", "letmein", "qwerty"})
	withMockCmd(t, &mockCmd{
		// doveadm exits non-zero for every candidate → no match.
		run: func(string, ...string) ([]byte, error) { return nil, errors.New("auth failed") },
	})

	if got := checkWordlist("{CRYPT}$6$salt$hash"); got != "" {
		t.Errorf("expected empty string when no password matches, got %q", got)
	}
}

func TestCheckWordlistMatchReturnsFirstMatch(t *testing.T) {
	withWeakPasswords(t, []string{"wrongpw", "matchme", "thirdpw"})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			// doveadm pw -t {hash} -p {candidate} → exit 0 means match.
			// Match only when candidate is "matchme" (it's the last arg).
			for _, a := range args {
				if a == "matchme" {
					return nil, nil
				}
			}
			return nil, errors.New("no match")
		},
	})

	if got := checkWordlist("{CRYPT}$6$salt$hash"); got != "matchme" {
		t.Errorf("expected 'matchme' to be returned, got %q", got)
	}
}

func TestCheckWordlistEmptyListReturnsEmpty(t *testing.T) {
	withWeakPasswords(t, nil)
	withMockCmd(t, &mockCmd{})
	if got := checkWordlist("{CRYPT}$any"); got != "" {
		t.Errorf("empty wordlist should yield empty result, got %q", got)
	}
}
