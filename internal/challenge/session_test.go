package challenge

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func mustSigner(t *testing.T, ttl time.Duration) *AdminSessionSigner {
	t.Helper()
	s, err := NewAdminSessionSigner(ttl)
	if err != nil {
		t.Fatalf("NewAdminSessionSigner: %v", err)
	}
	return s
}

func TestAdminSessionRoundTrip(t *testing.T) {
	s := mustSigner(t, time.Hour)
	cookie := s.Issue("1.2.3.4")
	if err := s.Verify(cookie, "1.2.3.4"); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestAdminSessionWrongIPRejected(t *testing.T) {
	s := mustSigner(t, time.Hour)
	cookie := s.Issue("1.2.3.4")
	err := s.Verify(cookie, "9.9.9.9")
	if !errors.Is(err, ErrSessionIPMismatch) {
		t.Errorf("err = %v, want ErrSessionIPMismatch", err)
	}
}

func TestAdminSessionTamperedSignatureRejected(t *testing.T) {
	s := mustSigner(t, time.Hour)
	cookie := s.Issue("1.2.3.4")
	// Flip a bit in the signature half of the cookie.
	dot := strings.LastIndexByte(cookie, '.')
	if dot < 0 {
		t.Fatalf("cookie missing dot: %q", cookie)
	}
	tampered := cookie[:dot+1] + "AA" + cookie[dot+3:]
	err := s.Verify(tampered, "1.2.3.4")
	if !errors.Is(err, ErrSessionBadSignature) && !errors.Is(err, ErrSessionMalformed) {
		t.Errorf("err = %v, want ErrSessionBadSignature or ErrSessionMalformed", err)
	}
}

func TestAdminSessionMalformedRejected(t *testing.T) {
	s := mustSigner(t, time.Hour)
	cases := []string{
		"",
		"nodot",
		".",
		"abc.",
		".abc",
	}
	for _, c := range cases {
		if err := s.Verify(c, "1.2.3.4"); !errors.Is(err, ErrSessionMalformed) {
			t.Errorf("%q -> err = %v, want ErrSessionMalformed", c, err)
		}
	}
}

func TestAdminSessionRotationInvalidatesPreviousCookies(t *testing.T) {
	s1 := mustSigner(t, time.Hour)
	cookie := s1.Issue("1.2.3.4")
	if err := s1.Verify(cookie, "1.2.3.4"); err != nil {
		t.Fatalf("pre-rotation Verify: %v", err)
	}
	s2 := mustSigner(t, time.Hour) // simulates daemon restart
	if err := s2.Verify(cookie, "1.2.3.4"); !errors.Is(err, ErrSessionBadSignature) {
		t.Errorf("post-rotation Verify err = %v, want ErrSessionBadSignature", err)
	}
}

func TestAdminSessionExpired(t *testing.T) {
	// TTL of -1s means every cookie is born already expired.
	s := mustSigner(t, time.Second)
	// Manually craft an expired cookie by reaching into encode helper.
	expired := encodeSessionPayload("1.2.3.4", time.Now().Add(-time.Hour))
	// Build with the real signer's key path: re-issue normally, then
	// override the expiry by issuing a fresh cookie via a shadow signer.
	// Simpler: issue with negative TTL via a custom builder.
	cookie := s.issueAt("1.2.3.4", time.Now().Add(-time.Hour))
	err := s.Verify(cookie, "1.2.3.4")
	if !errors.Is(err, ErrSessionExpired) {
		t.Errorf("err = %v, want ErrSessionExpired (payload %v)", err, expired)
	}
}

func TestCompareAdminSecret(t *testing.T) {
	cases := []struct {
		stored, presented string
		want              bool
	}{
		{"", "", false},
		{"", "anything", false},
		{"abc", "abc", true},
		{"abc", "ABC", false},
		{"abc", "abcd", false},
		{"long-secret-value-here", "long-secret-value-here", true},
	}
	for _, c := range cases {
		got := CompareAdminSecret(c.stored, c.presented)
		if got != c.want {
			t.Errorf("CompareAdminSecret(%q,%q) = %v, want %v", c.stored, c.presented, got, c.want)
		}
	}
}
