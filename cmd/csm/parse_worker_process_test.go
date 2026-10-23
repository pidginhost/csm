package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/parseworker"
	"github.com/pidginhost/csm/internal/workerproc"
)

func TestParseWorkerProcess(t *testing.T) {
	if os.Getenv("CSM_TEST_PARSE_WORKER") != "1" {
		return
	}
	os.Args = []string{"csm", "parse-worker", "--memory-limit=536870912"}
	main()
	os.Exit(0) // The test runner's PASS line must not enter the protocol socket.
}

// Exercise CLI startup as well as the listing: stdout is the protocol
// socket, so any diagnostic there would corrupt the hello or a reply.
func TestSupervisedParseWorkerKeepsSocketFraming(t *testing.T) {
	exec := workerproc.ExecLauncher(os.Args[0], []string{"-test.run=^TestParseWorkerProcess$"},
		append(os.Environ(), "CSM_TEST_PARSE_WORKER=1"))
	launch := func(ctx context.Context) (workerproc.Process, error) {
		p, err := exec(ctx)
		if err != nil {
			return nil, err
		}
		hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := workerproc.Handshake(hctx, p.Conn(), parseworker.Limits, parseworker.ProtocolVersion); err != nil {
			_ = p.Conn().Close()
			_ = p.Kill()
			<-p.Done()
			return nil, err
		}
		return p, nil
	}
	s, err := workerproc.New(workerproc.Config{Name: "parse worker", Launch: launch, Timeout: 10 * time.Second, Limits: parseworker.Limits})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{"a.php", "b/"} {
		if _, createErr := zw.Create(name); createErr != nil {
			t.Fatal(createErr)
		}
	}
	if closeErr := zw.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	path := filepath.Join(t.TempDir(), "kit.zip")
	if writeErr := os.WriteFile(path, buf.Bytes(), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	zf, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zf.Close()
	const offset = 7
	if _, err := zf.Seek(offset, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(parseworker.ListZipArgs{MaxDirBytes: 1 << 20})

	// Each record is a 3-byte header and the name: "a.php" and "b/".
	wantListing := []byte{0, 0, 5, 'a', '.', 'p', 'h', 'p', 1, 0, 2, 'b', '/'}
	for range 2 {
		var res parseworker.ListZipResult
		_, fds, err := s.Call(context.Background(), workerproc.Frame{Op: parseworker.OpListZip, Payload: payload}, []*os.File{zf},
			func(reply workerproc.Frame, fds []*os.File) (bool, error) {
				if err := json.Unmarshal(reply.Payload, &res); err != nil {
					return false, err
				}
				if len(fds) != 1 {
					return false, errors.New("want one listing descriptor")
				}
				return false, nil
			})
		if err != nil {
			t.Fatal(err)
		}
		st, statErr := fds[0].Stat()
		gotListing := make([]byte, len(wantListing))
		_, readErr := fds[0].ReadAt(gotListing, 0)
		_ = fds[0].Close()
		if statErr != nil || res.Entries != 2 || res.Incomplete != "" || st.Size() != int64(len(wantListing)) {
			t.Fatalf("listing: %+v size %v err %v", res, st, statErr)
		}
		if readErr != nil || !bytes.Equal(gotListing, wantListing) {
			t.Fatalf("listing bytes = %q, %v; want %q", gotListing, readErr, wantListing)
		}
		if got, err := zf.Seek(0, io.SeekCurrent); err != nil || got != offset {
			t.Fatalf("shared zip offset = %d, %v; want %d", got, err, offset)
		}
	}
	if got := s.Stats().Spawns; got != 1 {
		t.Fatalf("spawns = %d", got)
	}
}
