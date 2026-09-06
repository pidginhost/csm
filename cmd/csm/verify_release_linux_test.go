//go:build linux

package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Opening a FIFO must not wait for a writer before rejecting its file type.
func TestVerifyReleaseRejectsFIFOWithoutBlocking(t *testing.T) {
	dir, _, private, artifact := writeVerifyFixture(t)
	signature := filepath.Join(dir, "artifact.sig")
	if err := os.WriteFile(signature, ed25519.Sign(private, []byte("release payload")), 0600); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"key", "signature", "artifact"} {
		t.Run(input, func(t *testing.T) {
			key, sig, payload := filepath.Join(dir, "key.pem"), signature, artifact
			switch input {
			case "key":
				key = fifo
			case "signature":
				sig = fifo
			case "artifact":
				payload = fifo
			}
			done := make(chan error, 1)
			go func() { done <- verifyReleaseSignature(key, sig, payload) }()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "not a regular file") {
					t.Fatalf("FIFO verdict: %v", err)
				}
			case <-time.After(time.Second):
				// Release the blocked open so a failing test leaves no goroutine.
				fd, err := unix.Open(fifo, unix.O_RDWR|unix.O_NONBLOCK, 0)
				if err != nil {
					t.Fatal(err)
				}
				<-done
				_ = unix.Close(fd)
				t.Fatal("verifier blocked opening a non-regular file")
			}
		})
	}
}
