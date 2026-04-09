package signatures

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func TestVerifySignature_Valid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("version: 1\nrules:\n  - name: test\n")
	sig := ed25519.Sign(priv, data)
	pubHex := hex.EncodeToString(pub)

	if err := VerifySignature(pubHex, data, sig); err != nil {
		t.Errorf("VerifySignature() with valid signature: %v", err)
	}
}

func TestVerifySignature_InvalidSig(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("version: 1\nrules:\n  - name: test\n")
	badSig := make([]byte, ed25519.SignatureSize)
	pubHex := hex.EncodeToString(pub)

	if err := VerifySignature(pubHex, data, badSig); err == nil {
		t.Error("VerifySignature() with invalid signature: want error, got nil")
	}
}

func TestVerifySignature_WrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)

	data := []byte("some data")
	sig := ed25519.Sign(priv, data)
	otherHex := hex.EncodeToString(otherPub)

	if err := VerifySignature(otherHex, data, sig); err == nil {
		t.Error("VerifySignature() with wrong key: want error, got nil")
	}
}

func TestVerifySignature_BadHex(t *testing.T) {
	if err := VerifySignature("not-hex", nil, nil); err == nil {
		t.Error("VerifySignature() with bad hex: want error, got nil")
	}
}

func TestVerifySignature_WrongKeyLength(t *testing.T) {
	if err := VerifySignature("abcd", nil, nil); err == nil {
		t.Error("VerifySignature() with short key: want error, got nil")
	}
}

func TestVerifySignature_WrongSigLength(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	pubHex := hex.EncodeToString(pub)
	// 88 bytes (base64-encoded sig accidentally) — must not panic
	if err := VerifySignature(pubHex, []byte("data"), make([]byte, 88)); err == nil {
		t.Error("VerifySignature() with wrong sig length: want error, got nil")
	}
	// 0 bytes
	if err := VerifySignature(pubHex, []byte("data"), nil); err == nil {
		t.Error("VerifySignature() with nil sig: want error, got nil")
	}
}
