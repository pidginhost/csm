package integrity

import (
	"bytes"
	"encoding/json"
	"path/filepath"
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

func FuzzReadSignedConfig(f *testing.F) {
	path := filepath.Join(f.TempDir(), "csm.yaml")
	data := []byte("hostname: example.com\n")
	data = append(data, []byte("integrity:\n  config_hash: "+HashConfigStableBytes(data)+"\n")...)
	seed, err := json.Marshal(SignedConfig{Path: path, Bytes: data, Fragments: map[string][]byte{}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"path":"/etc/csm/csm.yaml","bytes":""}`))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := ReadSignedConfig(bytes.NewReader(data))
		if err != nil {
			return
		}
		cfg, err := decodeForSigning(c.Bytes)
		if err != nil || cfg.Integrity.ConfigHash != HashConfigStableBytes(c.Bytes) {
			t.Fatal("accepted unsigned content")
		}
		if !filepath.IsAbs(c.Path) || filepath.Clean(c.Path) != c.Path || (filepath.Ext(c.Path) != ".yaml" && filepath.Ext(c.Path) != ".yml") {
			t.Fatal("accepted invalid target")
		}
		if c.Fragments != nil {
			if cfg.Integrity.ConfdHash != c.ConfdHash {
				t.Fatal("accepted mismatched fragment digest")
			}
			if err := (fragmentRecord{ConfdHash: c.ConfdHash, Fragments: c.Fragments}).validate(); err != nil {
				t.Fatal(err)
			}
		}
	})
}
