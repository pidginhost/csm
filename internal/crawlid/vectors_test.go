package crawlid

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type targetVector struct {
	Note       string   `json:"note"`
	Raw        string   `json:"raw"`
	RawB64     string   `json:"raw_b64"`
	Method     string   `json:"method"`
	Levels     []uint8  `json:"levels"`
	MaxLen     int      `json:"max_len"`
	OK         bool     `json:"ok"`
	Err        string   `json:"err"`
	SegmentB64 string   `json:"segment_b64"`
	HasQuery   bool     `json:"has_query"`
	NamesB64   []string `json:"names_b64"`
	Ext        string   `json:"ext"`
	Dynamic    bool     `json:"dynamic"`
	Expensive  bool     `json:"expensive"`
}

type bindingVector struct {
	IP  string `json:"ip"`
	OK  bool   `json:"ok"`
	B64 string `json:"b64"`
}

type keyVector struct {
	Note       string   `json:"note"`
	Level      uint8    `json:"level"`
	SiteB64    string   `json:"site_b64"`
	SegmentB64 string   `json:"segment_b64"`
	NamesB64   []string `json:"names_b64"`
	EncodedB64 string   `json:"encoded_b64"`
	ID         string   `json:"id"`
}

type vectorFile struct {
	Version  int             `json:"version"`
	MaxLen   int             `json:"max_len"`
	Targets  []targetVector  `json:"targets"`
	Bindings []bindingVector `json:"bindings"`
	Keys     []keyVector     `json:"keys"`
}

func loadVectors(t testing.TB) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf vectorFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if decodeErr := dec.Decode(&vf); decodeErr != nil {
		t.Fatalf("decode vectors: %v", decodeErr)
	}
	if vf.Version != Version {
		t.Fatalf("vector version %d, contract version %d", vf.Version, Version)
	}
	if len(vf.Targets) == 0 || len(vf.Bindings) == 0 || len(vf.Keys) == 0 || vf.MaxLen <= 0 {
		t.Fatal("incomplete vector file")
	}
	return vf
}

func b64(t testing.TB, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("bad base64url %q: %v", s, err)
	}
	return b
}

var errNames = map[string]error{
	"empty":            ErrEmptyTarget,
	"unsupported-form": ErrUnsupportedForm,
	"too-long":         ErrTargetTooLong,
}

func TestTargetVectors(t *testing.T) {
	vf := loadVectors(t)
	for _, v := range vf.Targets {
		t.Run(v.Note, func(t *testing.T) {
			raw := v.Raw
			if v.RawB64 != "" {
				if raw != "" {
					t.Fatal("both raw and raw_b64 set")
				}
				raw = string(b64(t, v.RawB64))
			}
			limit := vf.MaxLen
			if v.MaxLen != 0 {
				limit = v.MaxLen
			}
			got, err := ParseTarget(raw, limit)
			if !v.OK {
				wantErr, known := errNames[v.Err]
				if !known {
					t.Fatalf("unknown vector error %q", v.Err)
				}
				if !errors.Is(err, wantErr) {
					t.Fatalf("ParseTarget(%q) err = %v, want %s", raw, err, v.Err)
				}
				if got.Segment != nil || got.HasQuery || got.Names != nil || got.Ext != "" {
					t.Fatalf("error returned partial identity: %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTarget(%q) unexpected err %v", raw, err)
			}
			if !bytes.Equal(got.Segment, b64(t, v.SegmentB64)) {
				t.Errorf("segment = %q, want %q", got.Segment, b64(t, v.SegmentB64))
			}
			if got.HasQuery != v.HasQuery {
				t.Errorf("HasQuery = %v, want %v", got.HasQuery, v.HasQuery)
			}
			if len(got.Names) != len(v.NamesB64) {
				t.Fatalf("names = %q, want %d names", got.Names, len(v.NamesB64))
			}
			for i, n := range v.NamesB64 {
				if !bytes.Equal(got.Names[i], b64(t, n)) {
					t.Errorf("name[%d] = %q, want %q", i, got.Names[i], b64(t, n))
				}
			}
			if got.Ext != v.Ext {
				t.Errorf("Ext = %q, want %q", got.Ext, v.Ext)
			}
			c := Classify(v.Method, got)
			if c.Dynamic != v.Dynamic || c.Expensive != v.Expensive {
				t.Errorf("Classify(%q) = %+v, want dynamic=%v expensive=%v", v.Method, c, v.Dynamic, v.Expensive)
			}
		})
	}
}

func TestParseTargetOverflowIsExplicit(t *testing.T) {
	raw := "/a/?x=" + strings.Repeat("b", 8192)
	if _, err := ParseTarget(raw, 8192); !errors.Is(err, ErrTargetTooLong) {
		t.Fatalf("err = %v, want ErrTargetTooLong", err)
	}
	if _, err := ParseTarget(raw[:8192], 8192); err != nil {
		t.Fatalf("target at the bound must parse, got %v", err)
	}
}

func TestClassifyMethods(t *testing.T) {
	tg, err := ParseTarget("/a/?x=1", 8192)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"POST", "PUT", "get", "OPTIONS", ""} {
		if c := Classify(m, tg); c.Dynamic || c.Expensive {
			t.Errorf("Classify(%q) = %+v, want zero", m, c)
		}
	}
	if c := Classify("HEAD", tg); !c.Dynamic || !c.Expensive {
		t.Errorf("Classify(HEAD) = %+v, want dynamic expensive", c)
	}
}

func TestPathExtensionASCII(t *testing.T) {
	for raw, want := range map[string]string{
		"/x.JPG": "jpg", "/x.%63ss": "%63ss", "/x.css/": "",
		"/x.\u0130CO": "\u0130co", "/a.b/x": "", "/x.": "",
	} {
		if got := PathExtension(raw); got != want {
			t.Errorf("%q: %q, want %q", raw, got, want)
		}
	}
}
