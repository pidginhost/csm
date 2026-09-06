package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// maxReleaseArtifactBytes bounds what the verifier will read into memory.
// Ed25519 is a pure signature scheme: the whole message must be buffered, and
// published packages are far below this limit.
const maxReleaseArtifactBytes = 512 << 20

// runVerifyRelease is the supported Ed25519 verification path on hosts whose
// OpenSSL cannot verify it from the command line. EL8 and CloudLinux 8 ship
// OpenSSL 1.1.1, whose pkeyutl has no -rawin, so the installer and deploy
// scripts call this instead of skipping verification.
//
//	csm verify-release <public-key.pem> <artifact.sig> <artifact>
func runVerifyRelease() {
	args := os.Args[2:]
	if len(args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: csm verify-release <public-key.pem> <signature-file> <artifact>")
		os.Exit(2)
	}
	if err := verifyReleaseSignature(args[0], args[1], args[2]); err != nil {
		fmt.Fprintf(os.Stderr, "signature verification failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("signature verified")
}

func verifyReleaseSignature(keyPath, signaturePath, artifactPath string) error {
	key, err := loadEd25519PublicKey(keyPath)
	if err != nil {
		return err
	}
	signature, err := readBoundedFile(signaturePath, ed25519.SignatureSize)
	if err != nil {
		return fmt.Errorf("reading signature: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("signature is %d bytes, want %d", len(signature), ed25519.SignatureSize)
	}
	artifact, err := readBoundedFile(artifactPath, maxReleaseArtifactBytes)
	if err != nil {
		return fmt.Errorf("reading artifact: %w", err)
	}
	// A download truncated to nothing must never be reported as authentic
	// merely because a matching signature was published alongside it.
	if len(artifact) == 0 {
		return errors.New("artifact is empty")
	}
	if !ed25519.Verify(key, artifact, signature) {
		return errors.New("artifact is not signed by the trusted release key")
	}
	return nil
}

func loadEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	data, err := readBoundedFile(path, 1<<16)
	if err != nil {
		return nil, fmt.Errorf("reading public key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("public key is not a PEM PUBLIC KEY block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, want ed25519", parsed)
	}
	return key, nil
}

// readBoundedFile reads a regular file and refuses anything longer than limit,
// so a hostile or corrupt input cannot exhaust memory during an upgrade.
func readBoundedFile(path string, limit int) ([]byte, error) {
	// Nonblocking open lets the type check reject FIFOs without waiting for
	// a writer. Regular files retain their normal read semantics.
	// #nosec G304 G703 -- The offline CLI reads caller-selected files and checks their type and size before verification.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	return data, nil
}
