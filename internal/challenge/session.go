package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"time"
)

// AdminSessionSigner mints and verifies the signed cookies that let
// authenticated operators bypass the PoW. The signing key is generated
// on construction; rebuilding the signer (i.e., daemon restart)
// invalidates every previously-issued cookie -- the rotation contract.
type AdminSessionSigner struct {
	key []byte
	ttl time.Duration
}

// ErrSessionExpired is returned by Verify for cookies whose embedded
// expiry has passed.
var ErrSessionExpired = errors.New("session expired")

// ErrSessionBadSignature is returned by Verify for cookies whose HMAC
// does not match. Includes tampered payloads and cookies signed by a
// previous AdminSessionSigner instance (post-rotation).
var ErrSessionBadSignature = errors.New("session signature invalid")

// ErrSessionIPMismatch is returned when the cookie was issued for a
// different IP than the one presenting it. Stops cookie theft from a
// different network.
var ErrSessionIPMismatch = errors.New("session IP mismatch")

// ErrSessionMalformed wraps decoding errors so a corrupt cookie has a
// distinct sentinel from a tampered one.
var ErrSessionMalformed = errors.New("session payload malformed")

// NewAdminSessionSigner generates a fresh 32-byte signing key. The
// caller must keep the returned pointer for the lifetime of the
// challenge server; never construct a second signer for the same
// server, or already-issued cookies will be invalidated mid-session.
func NewAdminSessionSigner(ttl time.Duration) (*AdminSessionSigner, error) {
	if ttl <= 0 {
		ttl = 4 * time.Hour
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &AdminSessionSigner{key: key, ttl: ttl}, nil
}

// TTL exposes the configured cookie lifetime so the server can set the
// matching Max-Age on the Set-Cookie header.
func (s *AdminSessionSigner) TTL() time.Duration { return s.ttl }

// Issue returns a cookie value of the form "<base64(payload)>.<base64 hmac>".
// The payload binds the cookie to a single IP and a single expiry so a
// stolen cookie does not work elsewhere or after the TTL.
func (s *AdminSessionSigner) Issue(ip string) string {
	return s.issueAt(ip, time.Now().Add(s.ttl))
}

// issueAt is the test seam for issuing a cookie with an explicit
// expiry. Lets expiry tests construct already-expired cookies without
// reaching into encodeSessionPayload directly.
func (s *AdminSessionSigner) issueAt(ip string, exp time.Time) string {
	payload := encodeSessionPayload(ip, exp)
	mac := hmac.New(sha256.New, s.key)
	mac.Write(payload)
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// Verify checks the HMAC, payload format, expiry, and IP binding. Use
// errors.Is to branch on the failure mode.
func (s *AdminSessionSigner) Verify(cookieValue, ip string) error {
	dot := strings.LastIndexByte(cookieValue, '.')
	if dot <= 0 || dot == len(cookieValue)-1 {
		return ErrSessionMalformed
	}
	payloadEnc := cookieValue[:dot]
	sigEnc := cookieValue[dot+1:]

	payload, err := base64.RawURLEncoding.DecodeString(payloadEnc)
	if err != nil {
		return ErrSessionMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigEnc)
	if err != nil {
		return ErrSessionMalformed
	}

	mac := hmac.New(sha256.New, s.key)
	mac.Write(payload)
	expected := mac.Sum(nil)
	if subtle.ConstantTimeCompare(sig, expected) != 1 {
		return ErrSessionBadSignature
	}

	cookieIP, exp, err := decodeSessionPayload(payload)
	if err != nil {
		return ErrSessionMalformed
	}
	if time.Now().After(exp) {
		return ErrSessionExpired
	}
	if cookieIP != ip {
		return ErrSessionIPMismatch
	}
	return nil
}

// CompareAdminSecret returns true when stored and presented secrets
// match in constant time. Empty stored secret always returns false so a
// misconfigured admin_secret cannot accidentally accept any caller.
func CompareAdminSecret(stored, presented string) bool {
	if stored == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(presented)) == 1
}

// encodeSessionPayload formats: 1 byte version | 8 byte unix expiry BE
// | n byte IP. Variable-length tail keeps it simple; the IP read stops
// at end-of-buffer.
func encodeSessionPayload(ip string, exp time.Time) []byte {
	out := make([]byte, 0, 9+len(ip))
	out = append(out, 1)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(exp.Unix()))
	out = append(out, ts[:]...)
	out = append(out, []byte(ip)...)
	return out
}

func decodeSessionPayload(p []byte) (ip string, exp time.Time, err error) {
	if len(p) < 9 || p[0] != 1 {
		return "", time.Time{}, ErrSessionMalformed
	}
	tsRaw := binary.BigEndian.Uint64(p[1:9])
	if tsRaw > uint64(1<<62) {
		return "", time.Time{}, ErrSessionMalformed
	}
	return string(p[9:]), time.Unix(int64(tsRaw), 0), nil
}
