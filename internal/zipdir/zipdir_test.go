package zipdir

import (
	"archive/zip"
	"bytes"
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
