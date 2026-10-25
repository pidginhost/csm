package yaraworker

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraipc"
)

func scanFDPart(t *testing.T) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "part.zip")
	if err := os.WriteFile(path, []byte("PK\x03\x04payload suffix"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestHandlerScanFDRejectsIncompletePart(t *testing.T) {
	for _, size := range []int{-1, 0, 32} {
		s := &fakeScanner{ruleCount: 1}
		h := NewHandler(s).(yaraipc.FDHandler)
		if _, err := h.ScanFD(scanFDPart(t), yaraipc.ScanFDArgs{MaxBytes: size}); err == nil {
			t.Errorf("size %d: incomplete scan succeeded", size)
		}
		if len(s.bytesCalls) != 0 {
			t.Errorf("size %d: scanned incomplete bytes %q", size, s.bytesCalls)
		}
	}
}

func TestHandlerScanFDReadsPositionally(t *testing.T) {
	f := scanFDPart(t)
	if _, err := f.Seek(3, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	s := &fakeScanner{ruleCount: 1, bytesMatches: []yara.Match{{RuleName: "archive", Meta: map[string]string{"severity": "critical"}}}}
	h := NewHandler(s).(yaraipc.FDHandler)
	res, err := h.ScanFD(f, yaraipc.ScanFDArgs{MaxBytes: 11})
	if err != nil || len(res.Matches) != 1 || res.Matches[0].Meta["severity"] != "critical" {
		t.Fatalf("scan = %+v, %v", res, err)
	}
	if len(s.bytesCalls) != 1 || string(s.bytesCalls[0]) != "PK\x03\x04payload" {
		t.Fatalf("scanned %q", s.bytesCalls)
	}
	if offset, err := f.Seek(0, io.SeekCurrent); err != nil || offset != 3 {
		t.Fatalf("offset = %d, %v", offset, err)
	}
	s.bytesErr = errors.New("engine failed")
	if _, err := h.ScanFD(f, yaraipc.ScanFDArgs{MaxBytes: 11}); !errors.Is(err, s.bytesErr) {
		t.Fatalf("engine failure = %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.ScanFD(f, yaraipc.ScanFDArgs{MaxBytes: 11}); err == nil {
		t.Fatal("closed part scanned clean")
	}
}

func TestHandlerScanFDWithoutEngineFailsClosed(t *testing.T) {
	for _, h := range []yaraipc.Handler{
		NewHandler(nil),
		NewHandler(&fakeScanner{}),
		newRecoverableHandler(nil, nil, "invalid rules"),
	} {
		if _, err := h.(yaraipc.FDHandler).ScanFD(scanFDPart(t), yaraipc.ScanFDArgs{MaxBytes: 11}); err == nil {
			t.Error("unavailable engine reported a clean descriptor scan")
		}
	}
}
