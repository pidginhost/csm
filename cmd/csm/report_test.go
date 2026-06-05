package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"io"
	"log"
	"os"
	"strings"
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
	privHex2, _, err := generateNodeKeyHex()
	if err != nil {
		t.Fatalf("second generate: %v", err)
	}
	if privHex == privHex2 {
		t.Fatal("key generation is not random")
	}
}

func TestReportArgsUnknownPrintsUsageAndFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runReportArgs([]string{"bogus"}, &stdout, &stderr); code == 0 {
		t.Fatal("unknown report subcommand returned success")
	}
	if stdout.Len() != 0 {
		t.Fatalf("unknown report subcommand wrote stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Usage: csm report enroll") {
		t.Fatalf("unknown report subcommand did not print usage: %q", stderr.String())
	}
}

func TestReportArgsEnrollRejectsExtraArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runReportArgs([]string{"enroll", "--unexpected"}, &stdout, &stderr); code == 0 {
		t.Fatal("report enroll with extra args returned success")
	}
	if stdout.Len() != 0 {
		t.Fatalf("report enroll with extra args wrote stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Usage: csm report enroll") {
		t.Fatalf("report enroll with extra args did not print usage: %q", stderr.String())
	}
}

func TestReportArgsHelpPrintsUsageAndSucceeds(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runReportArgs([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("help exit code = %d, want 0", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("help wrote stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Usage: csm report enroll") {
		t.Fatalf("help did not print usage: %q", stderr.String())
	}
}

func TestMainUsageMentionsReportEnroll(t *testing.T) {
	usage := captureStderr(t, printUsage)
	if !strings.Contains(usage, "report enroll") {
		t.Fatal("top-level usage does not mention report enroll")
	}
}

func TestReportEnrollPrintsPrivateKeyOnlyToStdout(t *testing.T) {
	var stdout, stderr, logs bytes.Buffer
	prevLog := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prevLog) })

	if code := reportEnroll(&stdout, &stderr); code != 0 {
		t.Fatalf("reportEnroll exit code = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("reportEnroll wrote stderr: %q", stderr.String())
	}
	if logs.Len() != 0 {
		t.Fatalf("reportEnroll logged output: %q", logs.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "environment variable named by the target's key_env") {
		t.Fatal("private-key storage guidance is missing")
	}
	if !strings.Contains(out, "public key") {
		t.Fatal("public key missing from output")
	}
	keyLines := reportOutputHexLines(out)
	if len(keyLines) != 2 {
		t.Fatalf("key line count = %d, want private and public key lines", len(keyLines))
	}
	priv, err := hex.DecodeString(keyLines[0])
	if err != nil {
		t.Fatal("private key line is not hex")
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("private key bytes = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	pub, err := hex.DecodeString(keyLines[1])
	if err != nil {
		t.Fatal("public key line is not hex")
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key bytes = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	derived := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)
	if !bytes.Equal(derived, pub) {
		t.Fatal("public key line does not match private key line")
	}
}

func reportOutputHexLines(out string) []string {
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, err := hex.DecodeString(line); err == nil {
			lines = append(lines, line)
		}
	}
	return lines
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stderr: %v", err)
	}
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = old })
	fn()
	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("close stderr pipe: %v", closeErr)
	}
	os.Stderr = old
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(data)
}
