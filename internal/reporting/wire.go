// Package reporting is the node side of CSM abuse reporting (Layer A). It turns
// confirmed-abuse findings into minimized, signed reports for a central abuse
// database or a private collector.
//
// The signed-envelope wire format here MUST stay byte-identical to the central
// service's verifier (csm-abuse-db internal/envelope). It is duplicated rather
// than imported to keep this repo's build self-contained; TestEnvelopeGolden
// pins the canonical bytes so any divergence fails the build.
package reporting

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	bodyHashLen = sha256.Size
	// maxFieldLen bounds each canonical field; matches the central verifier.
	maxFieldLen = 1 << 16
)

// ErrInvalidEnvelope means the envelope is structurally unusable.
var ErrInvalidEnvelope = errors.New("reporting: invalid envelope")

// Envelope is the set of fields signed alongside a report body. Field order and
// encoding match the central verifier exactly.
type Envelope struct {
	NodeID    string
	KeyID     string
	Method    string
	Path      string
	BodyHash  []byte // SHA-256 of the report body, 32 bytes
	Timestamp int64  // unix seconds, UTC
	Nonce     string
}

// HashBody returns the SHA-256 of body.
func HashBody(body []byte) []byte {
	sum := sha256.Sum256(body)
	return sum[:]
}

// canonical returns the deterministic, injective encoding signed over. Every
// variable-length field is length-prefixed with a 4-byte big-endian length, and
// the timestamp is appended as 8 big-endian bytes.
func (e Envelope) canonical() ([]byte, error) {
	if len(e.BodyHash) != bodyHashLen {
		return nil, ErrInvalidEnvelope
	}
	fields := [][]byte{
		[]byte(e.NodeID),
		[]byte(e.KeyID),
		[]byte(e.Method),
		[]byte(e.Path),
		e.BodyHash,
		[]byte(e.Nonce),
	}
	size := 8
	for _, f := range fields {
		if len(f) > maxFieldLen {
			return nil, ErrInvalidEnvelope
		}
		size += 4 + len(f)
	}
	buf := make([]byte, 0, size)
	var lenbuf [4]byte
	for _, f := range fields {
		// len(f) is bounded by maxFieldLen above, well under math.MaxUint32.
		// #nosec G115 -- length validated <= maxFieldLen (64 KiB) above.
		binary.BigEndian.PutUint32(lenbuf[:], uint32(len(f)))
		buf = append(buf, lenbuf[:]...)
		buf = append(buf, f...)
	}
	var ts [8]byte
	// Lossless int64 -> uint64 bit reinterpretation for fixed-width encoding.
	// #nosec G115 -- intentional bit-pattern reinterpret, not a narrowing cast.
	binary.BigEndian.PutUint64(ts[:], uint64(e.Timestamp))
	buf = append(buf, ts[:]...)
	return buf, nil
}

// SignEd25519 signs the canonical envelope with an Ed25519 private key.
func SignEd25519(e Envelope, priv ed25519.PrivateKey) ([]byte, error) {
	msg, err := e.canonical()
	if err != nil {
		return nil, err
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, ErrInvalidEnvelope
	}
	return ed25519.Sign(priv, msg), nil
}

// SignHMAC signs the canonical envelope with HMAC-SHA256 (private collector).
func SignHMAC(e Envelope, secret []byte) ([]byte, error) {
	msg, err := e.canonical()
	if err != nil {
		return nil, err
	}
	if len(secret) == 0 {
		return nil, ErrInvalidEnvelope
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(msg)
	return mac.Sum(nil), nil
}
