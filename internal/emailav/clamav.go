package emailav

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// ClamdScanner scans files via the clamd Unix socket using INSTREAM.
type ClamdScanner struct {
	socketPath string
}

// NewClamdScanner creates a ClamdScanner that connects to clamd at the given socket path.
func NewClamdScanner(socketPath string) *ClamdScanner {
	return &ClamdScanner{socketPath: socketPath}
}

func (s *ClamdScanner) Name() string { return "clamav" }

// Available checks if clamd is reachable by attempting a connection.
func (s *ClamdScanner) Available() bool {
	conn, err := net.DialTimeout("unix", s.socketPath, 2*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// Scan sends the file at path to clamd via INSTREAM and returns the verdict.
func (s *ClamdScanner) Scan(path string) (Verdict, error) {
	// #nosec G304 -- path is mail queue file path from mail scanner walk.
	f, err := os.Open(path)
	if err != nil {
		return Verdict{}, fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()

	conn, err := net.DialTimeout("unix", s.socketPath, 5*time.Second)
	if err != nil {
		return Verdict{}, fmt.Errorf("connecting to clamd: %w", err)
	}
	defer func() { _ = conn.Close() }()

	err = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err != nil {
		return Verdict{}, fmt.Errorf("setting deadline: %w", err)
	}

	// Send INSTREAM command
	_, err = conn.Write([]byte("nINSTREAM\n"))
	if err != nil {
		return Verdict{}, fmt.Errorf("sending INSTREAM: %w", err)
	}

	// Stream file content in chunks
	buf := make([]byte, 8192)
	lenBuf := make([]byte, 4)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(lenBuf, uint32(n))
			_, err = conn.Write(lenBuf)
			if err != nil {
				return Verdict{}, fmt.Errorf("sending chunk length: %w", err)
			}
			_, err = conn.Write(buf[:n])
			if err != nil {
				return Verdict{}, fmt.Errorf("sending chunk data: %w", err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return Verdict{}, fmt.Errorf("reading file: %w", readErr)
		}
	}

	// Send terminator (4 zero bytes)
	binary.BigEndian.PutUint32(lenBuf, 0)
	_, err = conn.Write(lenBuf)
	if err != nil {
		return Verdict{}, fmt.Errorf("sending terminator: %w", err)
	}

	// Read response
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil && err != io.EOF {
		return Verdict{}, fmt.Errorf("reading response: %w", err)
	}

	return parseClamdResponse(string(resp[:n]))
}

// parseClamdResponse parses a clamd INSTREAM response line.
// "stream: OK\n" → clean
// "stream: Win.Trojan.Agent-123 FOUND\n" → infected
func parseClamdResponse(resp string) (Verdict, error) {
	resp = strings.TrimSpace(resp)
	if strings.HasSuffix(resp, "OK") {
		return Verdict{Infected: false}, nil
	}
	if strings.HasSuffix(resp, "FOUND") {
		// Extract signature: "stream: <sig> FOUND"
		resp = strings.TrimPrefix(resp, "stream: ")
		sig := strings.TrimSuffix(resp, " FOUND")
		return Verdict{
			Infected:  true,
			Signature: sig,
			Severity:  "critical",
		}, nil
	}
	return Verdict{}, fmt.Errorf("unexpected clamd response: %q", resp)
}
