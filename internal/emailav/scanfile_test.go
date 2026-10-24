package emailav

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	emime "github.com/pidginhost/csm/internal/mime"
)

func partFile(t *testing.T, data string) Part {
	t.Helper()
	path := filepath.Join(t.TempDir(), "part")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	p := openPart(t, path)
	if _, err := p.File.Seek(3, io.SeekStart); err != nil { // offset must not matter
		t.Fatal(err)
	}
	return p
}

// openPart opens the file at path as a whole-file Part.
func openPart(t *testing.T, path string) Part {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return Part{File: f, Size: st.Size()}
}

func TestClamdScanStreamsFromFile(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "clamd.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	got := make(chan []byte, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		r := bufio.NewReader(conn)
		if cmd, _ := r.ReadString('\n'); cmd != "nINSTREAM\n" {
			got <- nil
			return
		}
		var payload []byte
		for {
			var n uint32
			if binary.Read(r, binary.BigEndian, &n) != nil || n == 0 {
				break
			}
			chunk := make([]byte, n)
			if _, readErr := io.ReadFull(r, chunk); readErr != nil {
				break
			}
			payload = append(payload, chunk...)
		}
		_, _ = conn.Write([]byte("stream: OK\n"))
		got <- payload
	}()
	s := NewClamdScanner(socket)
	p := partFile(t, "attachment bytes ignored suffix")
	p.Size = int64(len("attachment bytes"))
	v, err := s.Scan(p)
	if err != nil || v.Infected {
		t.Fatalf("Scan = %+v, %v", v, err)
	}
	select {
	case p := <-got:
		if string(p) != "attachment bytes" {
			t.Fatalf("clamd received %q", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("clamd got nothing")
	}
	if offset, err := p.File.Seek(0, io.SeekCurrent); err != nil || offset != 3 {
		t.Fatalf("caller offset = %d, %v", offset, err)
	}
}

type partRecorder struct {
	mu    sync.Mutex
	name  string
	parts []Part
}

func (r *partRecorder) Name() string    { return r.name }
func (r *partRecorder) Available() bool { return true }
func (r *partRecorder) Scan(p Part) (Verdict, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.parts = append(r.parts, p)
	return Verdict{}, nil
}

func TestOrchestratorScansPartFiles(t *testing.T) {
	a, b := &partRecorder{name: "a"}, &partRecorder{name: "b"}
	o := NewOrchestrator([]Scanner{a, b}, 5*time.Second)
	p := partFile(t, "data")
	res := o.ScanParts("msg", []emime.ExtractedPart{{Filename: "x.bin", Size: p.Size, File: p.File}}, false)
	if res.Infected || len(res.ErroredEngines) != 0 {
		t.Fatalf("result %+v", res)
	}
	for _, r := range []*partRecorder{a, b} {
		if len(r.parts) != 1 || r.parts[0].File != p.File || r.parts[0].Size != 4 {
			t.Fatalf("engine %s got %+v", r.name, r.parts)
		}
	}
}

func TestClamdIncompletePartIsEngineError(t *testing.T) {
	sock, stop := mockClamd(t, "stream: OK\n")
	defer stop()
	o := NewOrchestrator([]Scanner{NewClamdScanner(sock)}, 5*time.Second)
	for _, size := range []int64{-1, 0, 5} {
		p := partFile(t, "part")
		res := o.ScanParts("msg", []emime.ExtractedPart{{Filename: "part", File: p.File, Size: size}}, false)
		if res.Infected || !slices.Equal(res.ErroredEngines, []string{"clamav"}) || len(res.TimedOutEngines) != 0 {
			t.Errorf("size %d: incomplete scan must error, got %+v", size, res)
		}
	}
}
