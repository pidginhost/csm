package yara

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func fdPayload(t *testing.T, data string) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "part.zip") // an archive name must not skip the scan
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

type fdBackend struct {
	mockBackend
	err  error
	size int64
}

func (b *fdBackend) ScanFDChecked(_ *os.File, size int64) ([]Match, error) {
	b.size = size
	if b.err != nil {
		return nil, b.err
	}
	return []Match{{RuleName: "fd_hit"}}, nil
}

type bytesBackend struct {
	mockBackend
	got []byte
}

func (b *bytesBackend) ScanBytesChecked(data []byte) ([]Match, error) {
	b.got = data
	return []Match{{RuleName: "bytes_hit"}}, nil
}

func TestScanFileDescriptorCheckedUsesBackendFD(t *testing.T) {
	b := &fdBackend{}
	m, err := ScanFileDescriptorChecked(b, fdPayload(t, "PK\x03\x04data"), 8)
	if err != nil || len(m) != 1 || m[0].RuleName != "fd_hit" || b.size != 8 {
		t.Fatalf("matches %+v err %v size %d", m, err, b.size)
	}
}

func TestScanFileDescriptorCheckedReadsForInProcessBackend(t *testing.T) {
	b := &bytesBackend{}
	m, err := ScanFileDescriptorChecked(b, fdPayload(t, "PK\x03\x04data"), 8)
	if err != nil || len(m) != 1 || string(b.got) != "PK\x03\x04data" {
		t.Fatalf("matches %+v err %v got %q", m, err, b.got)
	}
}

// A worker that cannot take the descriptor must never read as clean.
func TestScanFileDescriptorCheckedFailsClosed(t *testing.T) {
	down := errors.New("yaraworker: supervisor not running")
	if _, err := ScanFileDescriptorChecked(&fdBackend{err: down}, fdPayload(t, "x"), 1); !errors.Is(err, down) {
		t.Fatalf("worker down = %v", err)
	}
	if _, err := ScanFileDescriptorChecked(nil, fdPayload(t, "x"), 1); err == nil {
		t.Fatal("nil backend scanned clean")
	}
}
