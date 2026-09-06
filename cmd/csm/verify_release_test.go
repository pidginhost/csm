package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeVerifyFixture(t *testing.T) (dir string, pub ed25519.PublicKey, priv ed25519.PrivateKey, artifact string) {
	t.Helper()
	dir = t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact = filepath.Join(dir, "csm.rpm")
	if err := os.WriteFile(artifact, []byte("release payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, pub, priv, artifact
}

// EL8 and CloudLinux 8 ship OpenSSL 1.1.1, whose CLI cannot verify Ed25519.
// The Go verifier is the supported path there, so it must accept exactly the
// artifacts openssl would and reject everything else.
func TestVerifyReleaseSignature(t *testing.T) {
	dir, _, priv, artifact := writeVerifyFixture(t)
	payload, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "csm.rpm.sig")
	if err := os.WriteFile(good, ed25519.Sign(priv, payload), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyReleaseSignature(filepath.Join(dir, "key.pem"), good, artifact); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	otherPub, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = otherPub
	wrongKeySig := filepath.Join(dir, "wrongkey.sig")
	if err := os.WriteFile(wrongKeySig, ed25519.Sign(otherPriv, payload), 0o600); err != nil {
		t.Fatal(err)
	}
	tampered := filepath.Join(dir, "tampered.rpm")
	if err := os.WriteFile(tampered, []byte("release payloae"), 0o600); err != nil {
		t.Fatal(err)
	}
	truncated := filepath.Join(dir, "truncated.sig")
	if err := os.WriteFile(truncated, ed25519.Sign(priv, payload)[:32], 0o600); err != nil {
		t.Fatal(err)
	}
	notAKey := filepath.Join(dir, "notakey.pem")
	if err := os.WriteFile(notAKey, []byte("-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rsaKey := filepath.Join(dir, "rsa.pem")
	if err := os.WriteFile(rsaKey, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not a key")}), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, key, sig, file string }{
		{"wrong key", filepath.Join(dir, "key.pem"), wrongKeySig, artifact},
		{"tampered payload", filepath.Join(dir, "key.pem"), good, tampered},
		{"truncated signature", filepath.Join(dir, "key.pem"), truncated, artifact},
		{"malformed key", notAKey, good, artifact},
		{"unsupported key type", rsaKey, good, artifact},
		{"missing signature", filepath.Join(dir, "key.pem"), filepath.Join(dir, "absent.sig"), artifact},
		{"missing artifact", filepath.Join(dir, "key.pem"), good, filepath.Join(dir, "absent.rpm")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifyReleaseSignature(tc.key, tc.sig, tc.file); err == nil {
				t.Fatal("unverified artifact accepted")
			}
		})
	}
}

// The signature must never be reported as valid because the payload was
// truncated to nothing by a failed download.
func TestVerifyReleaseSignatureRejectsEmptyArtifact(t *testing.T) {
	dir, _, priv, _ := writeVerifyFixture(t)
	empty := filepath.Join(dir, "empty.rpm")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sig := filepath.Join(dir, "empty.sig")
	if err := os.WriteFile(sig, ed25519.Sign(priv, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	err := verifyReleaseSignature(filepath.Join(dir, "key.pem"), sig, empty)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty artifact accepted: %v", err)
	}
}
