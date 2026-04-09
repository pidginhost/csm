package emailav

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// mockClamd starts a mock clamd server that responds to INSTREAM.
func mockClamd(t *testing.T, response string) (socketPath string, cleanup func()) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "clamd.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				// Read and discard the INSTREAM command and data
				buf := make([]byte, 65536)
				for {
					n, err := c.Read(buf)
					if err != nil || n == 0 {
						break
					}
					// Check for zero-length chunk (terminator): 4 zero bytes
					if n >= 4 {
						data := buf[:n]
						for i := 0; i <= len(data)-4; i++ {
							if data[i] == 0 && data[i+1] == 0 && data[i+2] == 0 && data[i+3] == 0 {
								_, _ = c.Write([]byte(response))
								return
							}
						}
					}
				}
			}(conn)
		}
	}()

	return sock, func() { _ = ln.Close() }
}

func TestClamdScannerClean(t *testing.T) {
	sock, cleanup := mockClamd(t, "stream: OK\n")
	defer cleanup()

	scanner := NewClamdScanner(sock)
	if !scanner.Available() {
		t.Fatal("scanner should be available")
	}
	if scanner.Name() != "clamav" {
		t.Errorf("Name() = %q, want %q", scanner.Name(), "clamav")
	}

	// Create a temp file to scan
	tmpFile := filepath.Join(t.TempDir(), "clean.txt")
	if err := os.WriteFile(tmpFile, []byte("hello world"), 0644); err != nil {
		t.Fatal(err)
	}

	verdict, err := scanner.Scan(tmpFile)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if verdict.Infected {
		t.Error("clean file should not be infected")
	}
}

func TestClamdScannerInfected(t *testing.T) {
	sock, cleanup := mockClamd(t, "stream: Win.Trojan.Agent-123 FOUND\n")
	defer cleanup()

	scanner := NewClamdScanner(sock)

	tmpFile := filepath.Join(t.TempDir(), "malware.exe")
	if err := os.WriteFile(tmpFile, []byte("fake malware content"), 0644); err != nil {
		t.Fatal(err)
	}

	verdict, err := scanner.Scan(tmpFile)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !verdict.Infected {
		t.Error("infected file should be detected")
	}
	if verdict.Signature != "Win.Trojan.Agent-123" {
		t.Errorf("Signature = %q, want %q", verdict.Signature, "Win.Trojan.Agent-123")
	}
	if verdict.Severity != "critical" {
		t.Errorf("Severity = %q, want %q", verdict.Severity, "critical")
	}
}

func TestClamdScannerUnavailable(t *testing.T) {
	scanner := NewClamdScanner("/nonexistent/clamd.sock")
	if scanner.Available() {
		t.Error("scanner with bad socket should not be available")
	}
}

func TestParseClamdResponseRejectsUnknownResponse(t *testing.T) {
	if _, err := parseClamdResponse("stream: ERROR size limit exceeded\n"); err == nil {
		t.Fatal("expected unknown clamd response to return error")
	}
}
