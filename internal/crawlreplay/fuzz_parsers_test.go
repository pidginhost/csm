package crawlreplay

import (
	"bytes"
	"encoding/json"
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

func FuzzDecodeManifest(f *testing.F) {
	f.Add(buildBundle(f, bundleStages{}).raw)
	f.Add([]byte(`null`))
	f.Add([]byte(`{"format_version":2,"format_version":2}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		m, err := DecodeManifest(raw)
		if err != nil {
			return
		}
		encoded, err := EncodeManifest(m)
		if err != nil || !bytes.Equal(encoded, raw) {
			t.Fatalf("accepted noncanonical manifest: %v", err)
		}
		if got := outputOf("", raw, 0).SHA256; m.Digest() != got {
			t.Fatal("manifest digest differs from accepted bytes")
		}
	})
}

func FuzzDecodeCoverageProof(f *testing.F) {
	seed, err := json.Marshal(wholeProof(f, buildBundle(f, bundleStages{})))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`null`))
	f.Add([]byte(`{"format_version":1,"format_version":1}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := DecodeCoverageProof(raw)
		if err != nil {
			return
		}
		if err = p.Validate(); err != nil {
			t.Fatalf("accepted invalid proof: %v", err)
		}
		if got := outputOf("", raw, 0).SHA256; p.Digest() != got {
			t.Fatal("proof digest differs from accepted bytes")
		}
		encoded, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = DecodeCoverageProof(encoded); err != nil {
			t.Fatalf("accepted proof cannot round trip: %v", err)
		}
	})
}
