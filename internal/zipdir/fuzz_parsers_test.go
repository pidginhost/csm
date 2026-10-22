package zipdir

import (
	"archive/zip"
	"bytes"
	"context"
	"testing"
)

func FuzzWalkDirectory(f *testing.F) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{"assets/", "assets/style.css", "login.php"} {
		if _, err := zw.Create(name); err != nil {
			f.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		f.Fatal(err)
	}
	f.Add(buf.Bytes())
	f.Add([]byte("PK\x05\x06"))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		dir, err := Read(r, int64(len(data)), 1<<20)
		if err != nil {
			return
		}
		var visited uint64
		err = Walk(context.Background(), r, dir, func(e Entry) error {
			visited++
			_ = e.Mode()
			return nil
		})
		if visited > dir.Records || (err == nil && visited != dir.Records) {
			t.Fatalf("visited=%d records=%d err=%v", visited, dir.Records, err)
		}
	})
}
