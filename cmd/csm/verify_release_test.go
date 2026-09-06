package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
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

func TestVerifyReleaseRejectsMalformedPublicKeyLengths(t *testing.T) {
	dir, _, private, artifact := writeVerifyFixture(t)
	signature := filepath.Join(dir, "artifact.sig")
	if err := os.WriteFile(signature, ed25519.Sign(private, []byte("release payload")), 0600); err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{0, 1, 31, 33, 64} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			der, err := asn1.Marshal(struct {
				Algorithm pkix.AlgorithmIdentifier
				Key       asn1.BitString
			}{
				Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 101, 112}},
				Key:       asn1.BitString{Bytes: make([]byte, size), BitLength: size * 8},
			})
			if err != nil {
				t.Fatal(err)
			}
			key := filepath.Join(t.TempDir(), "key")
			if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
				t.Fatal(err)
			}
			if err := verifyReleaseSignature(key, signature, artifact); err == nil {
				t.Fatalf("accepted an Ed25519 key of length %d", size)
			}
		})
	}
}

func TestReadBoundedFile(t *testing.T) {
	for _, size := range []int{0, 7, 8, 9, 100} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input")
			if err := os.WriteFile(path, []byte(strings.Repeat("x", size)), 0600); err != nil {
				t.Fatal(err)
			}
			data, err := readBoundedFile(path, 8)
			if size > 8 {
				if err == nil || !strings.Contains(err.Error(), "exceeds") || data != nil {
					t.Fatalf("oversized input: %q, %v", data, err)
				}
			} else if err != nil || string(data) != strings.Repeat("x", size) {
				t.Fatalf("bounded input: %q, %v", data, err)
			}
		})
	}
	if _, err := readBoundedFile(t.TempDir(), 8); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory verdict: %v", err)
	}
}

// EL8 and CloudLinux 8 ship OpenSSL 1.1.1, whose CLI cannot verify Ed25519.
// The Go verifier is the supported path there, so it must accept exactly the
// artifacts openssl would and reject everything else.
func TestVerifyReleaseSignature(t *testing.T) {
	dir, _, priv, artifact := writeVerifyFixture(t)
	payload, readErr := os.ReadFile(artifact)
	if readErr != nil {
		t.Fatal(readErr)
	}
	good := filepath.Join(dir, "csm.rpm.sig")
	if err := os.WriteFile(good, ed25519.Sign(priv, payload), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyReleaseSignature(filepath.Join(dir, "key.pem"), good, artifact); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	_, otherPriv, keyErr := ed25519.GenerateKey(rand.Reader)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
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
	otherType, typeErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if typeErr != nil {
		t.Fatal(typeErr)
	}
	otherDER, marshalErr := x509.MarshalPKIXPublicKey(&otherType.PublicKey)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	otherKey := filepath.Join(dir, "ecdsa.pem")
	if err := os.WriteFile(otherKey, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: otherDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, key, sig, file string }{
		{"wrong key", filepath.Join(dir, "key.pem"), wrongKeySig, artifact},
		{"tampered payload", filepath.Join(dir, "key.pem"), good, tampered},
		{"truncated signature", filepath.Join(dir, "key.pem"), truncated, artifact},
		{"malformed key", notAKey, good, artifact},
		{"unsupported key type", otherKey, good, artifact},
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
