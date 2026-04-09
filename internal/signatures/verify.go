package signatures

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"
)

func requireSigningKey(signingKey string) error {
	if signingKey == "" {
		return fmt.Errorf("signatures.signing_key is required for remote rule updates")
	}
	return nil
}

// VerifySignature checks an ed25519 signature over data using a hex-encoded public key.
// Returns nil if the signature is valid.
func VerifySignature(pubKeyHex string, data, signature []byte) error {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return fmt.Errorf("invalid signing key (bad hex): %w", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid signing key length: got %d bytes, want %d", len(pubKeyBytes), ed25519.PublicKeySize)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: got %d bytes, want %d", len(signature), ed25519.SignatureSize)
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)
	if !ed25519.Verify(pubKey, data, signature) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// fetchSignature downloads a detached signature from url + ".sig".
func fetchSignature(sigURL string) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(sigURL)
	if err != nil {
		return nil, fmt.Errorf("downloading signature from %s: %w", sigURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signature download returned HTTP %d from %s", resp.StatusCode, sigURL)
	}

	sig, err := io.ReadAll(io.LimitReader(resp.Body, 1024)) // ed25519 sig is 64 bytes
	if err != nil {
		return nil, fmt.Errorf("reading signature: %w", err)
	}
	return sig, nil
}
