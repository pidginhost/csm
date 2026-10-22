package zipdir

import (
	"archive/zip"
	"bytes"
	"context"
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
