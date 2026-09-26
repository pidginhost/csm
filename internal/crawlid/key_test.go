package crawlid

import (
	"bytes"
	"errors"
	"testing"
)

func mustTarget(t *testing.T, raw string) Target {
	t.Helper()
	tg, err := ParseTarget(raw, 8192)
	if err != nil {
		t.Fatalf("ParseTarget(%q): %v", raw, err)
	}
	return tg
}

func TestKeysForLevels(t *testing.T) {
	site := []byte("example.com")
	tg := mustTarget(t, "/category/?filter_color=red")
	keys := KeysFor(site, Classify("GET", tg), tg)
	if len(keys) != 3 || keys[0].Level != L3 || keys[1].Level != L2 || keys[2].Level != L1 {
		t.Fatalf("levels = %+v, want L3, L2, L1", keys)
	}
	if keys[0].Segment != nil || keys[0].Names != nil {
		t.Errorf("L3 carries segment/names: %+v", keys[0])
	}
	if !bytes.Equal(keys[1].Segment, []byte("category")) || keys[1].Names != nil {
		t.Errorf("L2 = %+v", keys[1])
	}
	if len(keys[2].Names) != 1 || !bytes.Equal(keys[2].Names[0], []byte("filter_color")) {
		t.Errorf("L1 names = %q", keys[2].Names)
	}

	plain := mustTarget(t, "/category/")
	if got := KeysFor(site, Classify("GET", plain), plain); len(got) != 1 || got[0].Level != L3 {
		t.Errorf("queryless dynamic keys = %+v, want only L3", got)
	}
	static := mustTarget(t, "/a.css?v=1")
	if got := KeysFor(site, Classify("GET", static), static); got != nil {
		t.Errorf("static keys = %+v, want nil", got)
	}
}

func TestKeyEncodeRoundTripAndNoDelimiterCollision(t *testing.T) {
	a := Key{Level: L1, Site: []byte("a|b"), Segment: []byte("c"), Names: [][]byte{[]byte("d")}}
	b := Key{Level: L1, Site: []byte("a"), Segment: []byte("b|c"), Names: [][]byte{[]byte("d")}}
	if bytes.Equal(a.Encode(), b.Encode()) || a.ID() == b.ID() {
		t.Fatal("distinct keys share an encoding")
	}
	for _, k := range []Key{
		a, b,
		{Level: L2, Site: []byte("s"), Segment: []byte{}},
		{Level: L3, Site: []byte("s")},
		{Level: L1, Site: []byte("s"), Segment: []byte("x"), Names: [][]byte{{}, {0xff}}},
	} {
		got, err := DecodeKey(k.Encode())
		if err != nil {
			t.Fatalf("DecodeKey(%+v): %v", k, err)
		}
		if !bytes.Equal(got.Encode(), k.Encode()) {
			t.Errorf("round trip changed %+v into %+v", k, got)
		}
	}
}

func TestDecodeKeyRejectsMalformed(t *testing.T) {
	good := Key{Level: L1, Site: []byte("s"), Segment: []byte("x"), Names: [][]byte{[]byte("n")}}.Encode()
	cases := map[string][]byte{
		"empty":         nil,
		"bad magic":     append([]byte("xx"), good[2:]...),
		"bad version":   append([]byte{'c', 'k', 99}, good[3:]...),
		"bad level":     append([]byte{'c', 'k', Version, 9}, good[4:]...),
		"truncated":     good[:len(good)-1],
		"trailing data": append(append([]byte{}, good...), 0),
	}
	for name, b := range cases {
		if _, err := DecodeKey(b); !errors.Is(err, ErrBadKey) {
			t.Errorf("%s: err = %v, want ErrBadKey", name, err)
		}
	}
}

func TestKeyVectors(t *testing.T) {
	for _, v := range loadVectors(t).Keys {
		t.Run(v.Note, func(t *testing.T) {
			k := Key{Level: Level(v.Level), Site: b64(t, v.SiteB64), Segment: b64(t, v.SegmentB64)}
			for _, n := range v.NamesB64 {
				k.Names = append(k.Names, b64(t, n))
			}
			want := b64(t, v.EncodedB64)
			if !bytes.Equal(k.Encode(), want) || k.ID() != v.ID {
				t.Fatalf("encoding/ID differs from frozen vector: %x %s", k.Encode(), k.ID())
			}
			got, err := DecodeKey(want)
			if err != nil || !bytes.Equal(got.Encode(), want) || got.ID() != v.ID {
				t.Fatalf("decode golden: %+v %v", got, err)
			}
		})
	}
}

func TestDecodeKeyRejectsNoncanonical(t *testing.T) {
	for _, raw := range [][]byte{
		{'c', 'k', 1, 3, 0x81, 0, 's'},                 // overlong field length
		{'c', 'k', 1, 1, 1, 's', 0, 0x80, 0},           // overlong name count
		{'c', 'k', 1, 1, 1, 's', 0, 2, 1, 'b', 1, 'a'}, // unsorted names
		{'c', 'k', 1, 1, 1, 's', 0, 2, 1, 'a', 1, 'a'}, // duplicate names
		{'c', 'k', 1, 3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
		{'c', 'k', 1, 1, 1, 's', 0, 127}, // count larger than remaining bytes
	} {
		if _, err := DecodeKey(raw); !errors.Is(err, ErrBadKey) {
			t.Errorf("accepted %x: %v", raw, err)
		}
	}
	good := Key{Level: L1, Site: []byte("example.com"), Segment: []byte("a"), Names: [][]byte{[]byte("x")}}.Encode()
	for i := range len(good) {
		if _, err := DecodeKey(good[:i]); !errors.Is(err, ErrBadKey) {
			t.Errorf("accepted prefix %d", i)
		}
	}
}

func TestKeysForExactIdentity(t *testing.T) {
	site := []byte("example.com")
	a := mustTarget(t, "/a?X=1&y=2&x=3")
	b := mustTarget(t, "/a?y=other&x=different")
	ka, kb := KeysFor(site, Classify("GET", a), a), KeysFor(site, Classify("GET", b), b)
	for i := range ka {
		if !bytes.Equal(ka[i].Site, site) || !bytes.Equal(ka[i].Encode(), kb[i].Encode()) {
			t.Fatalf("values/order changed level %d identity", i)
		}
	}
	subset := mustTarget(t, "/a?x=1")
	kc := KeysFor(site, Classify("GET", subset), subset)
	if bytes.Equal(ka[2].Encode(), kc[2].Encode()) {
		t.Fatal("L1 matched a subset of names")
	}
	if !bytes.Equal(ka[0].Encode(), kc[0].Encode()) || !bytes.Equal(ka[1].Encode(), kc[1].Encode()) {
		t.Fatal("name changes split ancestor keys")
	}
	kd := KeysFor([]byte("other.example"), Classify("GET", a), a)
	for i := range ka {
		if bytes.Equal(ka[i].Encode(), kd[i].Encode()) {
			t.Fatal("site collision")
		}
	}
	if got := KeysFor(site, Classify("POST", a), a); got != nil {
		t.Fatal("POST created keys")
	}
}

func TestKeysForTargetVectors(t *testing.T) {
	vf := loadVectors(t)
	site := []byte("example.com")
	for _, v := range vf.Targets {
		if !v.OK {
			continue
		}
		t.Run(v.Note, func(t *testing.T) {
			raw := v.Raw
			if v.RawB64 != "" {
				raw = string(b64(t, v.RawB64))
			}
			limit := vf.MaxLen
			if v.MaxLen != 0 {
				limit = v.MaxLen
			}
			target, err := ParseTarget(raw, limit)
			if err != nil {
				t.Fatal(err)
			}
			keys := KeysFor(site, Classify(v.Method, target), target)
			if len(keys) != len(v.Levels) {
				t.Fatalf("got %d levels, want %v", len(keys), v.Levels)
			}
			for i, level := range v.Levels {
				want := Key{Level: Level(level), Site: site}
				if level != uint8(L3) {
					want.Segment = b64(t, v.SegmentB64)
				}
				if level == uint8(L1) {
					for _, n := range v.NamesB64 {
						want.Names = append(want.Names, b64(t, n))
					}
				}
				if !bytes.Equal(keys[i].Encode(), want.Encode()) {
					t.Fatalf("wrong fields at level %d", level)
				}
			}
		})
	}
}
