package zipdir

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

func TestReadReportsRecordCountWithoutReadingEntries(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < 3; i++ {
		if _, err := zw.CreateHeader(&zip.FileHeader{Name: fmt.Sprintf("f%d", i), Method: zip.Store}); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	dir, err := Read(bytes.NewReader(buf.Bytes()), int64(buf.Len()), 16<<20)
	if err != nil || dir.Records != 3 {
		t.Fatalf("Read = %+v, %v; want 3 records", dir, err)
	}
	if _, err := Read(bytes.NewReader(buf.Bytes()), int64(buf.Len()), 10); !errors.Is(err, ErrScanLimit) {
		t.Fatalf("tiny limit: err = %v, want ErrScanLimit", err)
	}
	if _, err := Read(bytes.NewReader([]byte("not a zip")), 9, 16<<20); !errors.Is(err, ErrFormat) {
		t.Fatalf("garbage: err = %v, want ErrFormat", err)
	}
}

func TestOffsetRejectsOverflow(t *testing.T) {
	got, ok := toOffset(1<<63 - 1)
	if !ok || got != 1<<63-1 {
		t.Fatalf("max int64 offset: got (%d, %v)", got, ok)
	}
	if _, ok := toOffset(1 << 63); ok {
		t.Error("offset above max int64 was accepted")
	}
}

func TestWalkVisitsEveryEntryInOrderAndStopsOnRequest(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range []string{"a/", "a/b.php", "c.txt"} {
		if _, err := zw.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Store}); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(buf.Bytes())
	dir, err := Read(r, int64(buf.Len()), 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	var dirs []bool
	if err := Walk(context.Background(), r, dir, func(e Entry) error {
		names = append(names, e.Name)
		dirs = append(dirs, e.Mode().IsDir())
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if fmt.Sprint(names) != "[a/ a/b.php c.txt]" || fmt.Sprint(dirs) != "[true false false]" {
		t.Fatalf("names=%v dirs=%v", names, dirs)
	}
	stop := errors.New("stop")
	visited := 0
	if err := Walk(context.Background(), r, dir, func(Entry) error { visited++; return stop }); !errors.Is(err, stop) || visited != 1 {
		t.Fatalf("early stop: err=%v visited=%d", err, visited)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Walk(ctx, r, dir, func(Entry) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled walk: err=%v", err)
	}
}

func TestWalkRejectsUnreadDirectoryBytes(t *testing.T) {
	var header [HeaderLen]byte
	binary.LittleEndian.PutUint32(header[:4], HeaderSignature)
	for _, tail := range [][]byte{{'x'}, {'x', 'y', 'z'}, []byte("junk"), {0x50, 0x4b, 0x01}} {
		raw := append(append([]byte(nil), header[:]...), tail...)
		visited := 0
		err := Walk(context.Background(), bytes.NewReader(raw), Directory{Size: int64(len(raw)), Records: 1}, func(Entry) error {
			visited++
			return nil
		})
		if !errors.Is(err, ErrFormat) || visited != 1 {
			t.Errorf("tail %x: err=%v visited=%d, want ErrFormat after one entry", tail, err, visited)
		}
	}
	// Reader EOF before the declared end is truncation even if the count matches.
	err := Walk(context.Background(), bytes.NewReader(header[:]), Directory{Size: HeaderLen + 4, Records: 1}, func(Entry) error { return nil })
	if !errors.Is(err, ErrFormat) {
		t.Errorf("short directory: err=%v, want ErrFormat", err)
	}
}

func TestWalkValidatesDigitalSignatureTrailer(t *testing.T) {
	var header [HeaderLen]byte
	binary.LittleEndian.PutUint32(header[:4], HeaderSignature)
	trailer := []byte{0x50, 0x4b, 0x05, 0x05, 3, 0, 'a', 'b', 'c'}
	for _, tc := range []struct {
		name  string
		tail  []byte
		valid bool
	}{
		{"valid", trailer, true},
		{"cut header", trailer[:5], false},
		{"cut data", trailer[:8], false},
		{"extra data", append(append([]byte(nil), trailer...), 'x'), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := append(append([]byte(nil), header[:]...), tc.tail...)
			visited := 0
			err := Walk(context.Background(), bytes.NewReader(raw), Directory{Size: int64(len(raw)), Records: 1}, func(Entry) error {
				visited++
				return nil
			})
			if visited != 1 || (tc.valid && err != nil) || (!tc.valid && !errors.Is(err, ErrFormat)) {
				t.Fatalf("err=%v visited=%d valid=%v", err, visited, tc.valid)
			}
		})
	}
}

func TestWalkChecksCancellationDuringListing(t *testing.T) {
	var header [HeaderLen]byte
	binary.LittleEndian.PutUint32(header[:4], HeaderSignature)
	raw := bytes.Repeat(header[:], 600)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	visited := 0
	err := Walk(ctx, bytes.NewReader(raw), Directory{Size: int64(len(raw)), Records: 600}, func(Entry) error {
		visited++
		if visited == 1 {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || visited != 256 {
		t.Fatalf("err=%v visited=%d, want cancellation after 256 entries", err, visited)
	}
}

// archive/zip opens a zip with bytes after its end record (download scripts
// often append a line break), so Read must find the same end record.
func TestReadAcceptsBytesAfterEndRecord(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if _, err := zw.Create("a.txt"); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tail := range []string{"\r\n", string(make([]byte, 512))} {
		data := append(append([]byte(nil), buf.Bytes()...), tail...)
		dir, err := Read(bytes.NewReader(data), int64(len(data)), 16<<20)
		if err != nil || dir.Records != 1 {
			t.Fatalf("tail %q: Read = %+v, %v", tail[:min(len(tail), 4)], dir, err)
		}
		if _, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err != nil {
			t.Fatalf("archive/zip refused the same file: %v", err)
		}
	}
}

// Only padding may follow the end record when no record reaches EOF exactly:
// other bytes could hold a decoy end record that a lenient unzip picks.
func TestReadRefusesNonPaddingAfterEndRecord(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if _, err := zw.Create("a.txt"); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	decoy := make([]byte, EndLen)
	binary.LittleEndian.PutUint32(decoy, EndSignature)
	binary.LittleEndian.PutUint16(decoy[20:22], 0xffff) // comment overruns EOF
	for name, tail := range map[string][]byte{
		"junk":  []byte("junk"),
		"decoy": decoy,
	} {
		data := append(append([]byte(nil), buf.Bytes()...), tail...)
		if _, err := Read(bytes.NewReader(data), int64(len(data)), 16<<20); !errors.Is(err, ErrFormat) {
			t.Errorf("%s after end record: err = %v, want ErrFormat", name, err)
		}
	}
}
