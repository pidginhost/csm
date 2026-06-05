package reporting

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func fixedEnvelope() Envelope {
	return Envelope{
		NodeID:    "n_7f3a",
		KeyID:     "k1",
		Method:    "POST",
		Path:      "/report",
		BodyHash:  HashBody([]byte(`{"ip":"203.0.113.5"}`)),
		Timestamp: 1_700_000_000,
		Nonce:     "nonce-1",
	}
}

// manualCanonical re-derives the canonical bytes through an independent code
// path. If reporting.canonical drifts from the documented wire format (and thus
// from the central verifier), this mismatch fails the build.
func manualCanonical(e Envelope) []byte {
	var buf []byte
	put := func(b []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b)))
		buf = append(buf, l[:]...)
		buf = append(buf, b...)
	}
	put([]byte(e.NodeID))
	put([]byte(e.KeyID))
	put([]byte(e.Method))
	put([]byte(e.Path))
	put(e.BodyHash)
	put([]byte(e.Nonce))
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(e.Timestamp))
	buf = append(buf, ts[:]...)
	return buf
}

func TestCanonicalMatchesWireFormat(t *testing.T) {
	e := fixedEnvelope()
	got, err := e.canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	want := manualCanonical(e)
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical drift:\n got=%x\nwant=%x", got, want)
	}
	const goldenHex = "" +
		"000000066e5f37663361000000026b3100000004504f5354" +
		"000000072f7265706f7274000000203afbb0c331433d7fdf" +
		"d670a648fbb4dddfd15a356aebe7abc800217711eec38a" +
		"000000076e6f6e63652d31000000006553f100"
	golden, err := hex.DecodeString(goldenHex)
	if err != nil {
		t.Fatalf("golden fixture: %v", err)
	}
	if !bytes.Equal(got, golden) {
		t.Fatalf("canonical golden drift:\n got=%x\nwant=%x", got, golden)
	}
}

func TestEd25519SignRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	e := fixedEnvelope()
	sig, err := SignEd25519(e, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	msg, _ := e.canonical()
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("ed25519 signature did not verify over canonical bytes")
	}
	// A changed field must invalidate the signature.
	e2 := e
	e2.NodeID = "n_other"
	msg2, _ := e2.canonical()
	if ed25519.Verify(pub, msg2, sig) {
		t.Fatal("signature validated a different envelope")
	}
}

func TestHMACSignRoundTrip(t *testing.T) {
	secret := []byte("collector-secret")
	e := fixedEnvelope()
	sig, err := SignHMAC(e, secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	msg, _ := e.canonical()
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(msg)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		t.Fatal("hmac signature mismatch")
	}
}

func TestSignRejectsBadBodyHash(t *testing.T) {
	e := fixedEnvelope()
	e.BodyHash = []byte{1, 2, 3}
	if _, err := SignEd25519(e, make(ed25519.PrivateKey, ed25519.PrivateKeySize)); err != ErrInvalidEnvelope {
		t.Fatalf("got %v, want ErrInvalidEnvelope", err)
	}
}

func TestSignRejectsBadKey(t *testing.T) {
	e := fixedEnvelope()
	if _, err := SignEd25519(e, ed25519.PrivateKey{1, 2, 3}); err != ErrInvalidEnvelope {
		t.Fatalf("got %v, want ErrInvalidEnvelope", err)
	}
	if _, err := SignHMAC(e, nil); err != ErrInvalidEnvelope {
		t.Fatalf("hmac empty secret: got %v, want ErrInvalidEnvelope", err)
	}
}
