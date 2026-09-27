package crawlreplay

import (
	"bytes"
	"testing"
)

func FuzzReadRecords(f *testing.F) {
	var buf bytes.Buffer
	if err := WriteRow(&buf, validRecord()); err != nil {
		f.Fatal(err)
	}
	f.Add(buf.Bytes())
	f.Add([]byte(`{"t":1,"f":0,"n":1,"site":"dom-000000.example","c":1,"s":200,"r":0}`))
	f.Add([]byte(`{"t":1,"n":1,"site":"example.com","c":2,"s":200}` + "\n{"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ReadRecords(bytes.NewReader(data), func(r Record) error {
			if err := r.Validate(); err != nil {
				t.Fatalf("reader delivered an invalid record: %v", err)
			}
			var out bytes.Buffer
			if err := WriteRow(&out, r); err != nil {
				t.Fatalf("delivered record does not write back: %v", err)
			}
			return nil
		})
	})
}
