package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func TestGenerateNodeKeyHex(t *testing.T) {
	privHex, pubHex, err := generateNodeKeyHex()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	priv, err := hex.DecodeString(privHex)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("private key hex invalid: len=%d err=%v", len(priv), err)
	}
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key hex invalid: len=%d err=%v", len(pub), err)
	}
	// The public key must correspond to the private key.
	derived := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)
	if hex.EncodeToString(derived) != pubHex {
		t.Fatal("public key does not match private key")
	}

	// Two calls produce distinct keys.
	privHex2, _, _ := generateNodeKeyHex()
	if privHex == privHex2 {
		t.Fatal("key generation is not random")
	}
}
