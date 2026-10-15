package integrity

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func FuzzFragmentRecord(f *testing.F) {
	digest, contents := confdSnapshot([]config.ConfDirFragment{{Name: "10-test.yaml", Data: []byte("hostname: test.example.com\n")}}, nil)
	seed, err := json.Marshal(fragmentRecord{ConfdHash: digest, Fragments: contents})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"confd_hash":"","fragments":{}}`))
	f.Add([]byte(`{"confd_hash":"","fragments":{"../bad.yaml":"YQ=="}}`))
	f.Add([]byte(`{"fragments":{}}`))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, data []byte) {
		rec, err := decodeFragmentRecord(data)
		if err != nil {
			return
		}
		encoded, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		again, err := decodeFragmentRecord(encoded)
		if err != nil || rec.ConfdHash != again.ConfdHash || len(rec.Fragments) != len(again.Fragments) {
			t.Fatalf("record did not round trip: %v", err)
		}
		for name, content := range rec.Fragments {
			if !bytes.Equal(content, again.Fragments[name]) {
				t.Fatal("round trip changed fragment contents")
			}
		}
	})
}
