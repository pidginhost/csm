package challenge

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
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

// tamperSignature flips one bit of the decoded signature, so the result
// always differs from the signed value whatever that value is.
func tamperSignature(t *testing.T, cookie string) string {
	t.Helper()
	dot := strings.LastIndexByte(cookie, '.')
	if dot < 0 {
		t.Fatalf("cookie missing dot: %q", cookie)
	}
	sig, err := base64.RawURLEncoding.DecodeString(cookie[dot+1:])
	if err != nil || len(sig) == 0 {
		t.Fatalf("cookie signature does not decode: %q", cookie)
	}
	sig[0] ^= 1
	return cookie[:dot+1] + base64.RawURLEncoding.EncodeToString(sig)
}

func TestAdminSessionTamperedSignatureRejected(t *testing.T) {
	s := mustSigner(t, time.Hour)
	cookie := s.Issue("192.0.2.1")
	if err := s.Verify(cookie, "192.0.2.1"); err != nil {
		t.Fatalf("pre-tampering Verify: %v", err)
	}
	if err := s.Verify(tamperSignature(t, cookie), "192.0.2.1"); !errors.Is(err, ErrSessionBadSignature) {
		t.Errorf("err = %v, want ErrSessionBadSignature", err)
	}
}

func TestTamperSignatureChangesEveryFirstByte(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString(encodeSessionPayload("2001:db8::1", time.Now().Add(time.Hour)))
	for first := 0; first < 256; first++ {
		t.Run(fmt.Sprintf("%02x", first), func(t *testing.T) {
			// Zero bytes produce the AA prefix that a fixed overwrite left unchanged.
			sig := make([]byte, 32)
			sig[0] = byte(first)
			cookie := payload + "." + base64.RawURLEncoding.EncodeToString(sig)
			tampered := tamperSignature(t, cookie)
			payloadAfter, signatureAfter, ok := strings.Cut(tampered, ".")
			if !ok || payloadAfter != payload {
				t.Fatalf("tampering changed the payload")
			}
			decoded, err := base64.RawURLEncoding.DecodeString(signatureAfter)
			if err != nil || len(decoded) != len(sig) {
				t.Fatalf("tampering produced a malformed signature")
			}
			if bytes.Equal(decoded, sig) {
				t.Error("tampering left the signature unchanged")
			}
		})
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
