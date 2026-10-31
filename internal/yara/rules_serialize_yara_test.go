//go:build yara

package yara

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
)

func TestCompiledRulesRoundTrip(t *testing.T) {
	compiled, err := CompileSources([]Source{{
		Name: "marker.yar",
		Text: []byte(`rule csm_roundtrip_marker { meta: severity = "critical" strings: $a = "CSM-ROUNDTRIP-7c1e" condition: $a }`),
	}})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if n, writeErr := compiled.WriteTo(&buf); writeErr != nil {
		t.Fatal(writeErr)
	} else if n != int64(buf.Len()) || n == 0 {
		t.Fatalf("WriteTo count = %d, buffer length = %d", n, buf.Len())
	}
	loaded, err := LoadRules(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Count() != 1 || loaded.Count() != 1 {
		t.Fatalf("counts compiled=%d loaded=%d, want 1", compiled.Count(), loaded.Count())
	}
	runtime.GC()
	matches, err := loaded.Scan([]byte("xx CSM-ROUNDTRIP-7c1e xx"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].RuleName != "csm_roundtrip_marker" || matches[0].Meta["severity"] != "critical" {
		t.Fatalf("matches = %+v", matches)
	}
	clean, err := loaded.Scan([]byte("nothing here"))
	if err != nil || len(clean) != 0 {
		t.Fatalf("clean scan = %+v, %v", clean, err)
	}
}

func TestLoadRulesPreservesReadError(t *testing.T) {
	want := errors.New("read failed")
	rules, err := LoadRules(ruleReaderFunc(func([]byte) (int, error) { return 0, want }))
	if rules != nil || !errors.Is(err, want) {
		t.Fatalf("LoadRules = %v, %v; want nil, %v", rules, err, want)
	}
}

type ruleReaderFunc func([]byte) (int, error)

func (f ruleReaderFunc) Read(p []byte) (int, error) { return f(p) }

func TestCompileSourcesNamesFailingFile(t *testing.T) {
	_, err := CompileSources([]Source{
		{Name: "good.yar", Text: []byte("rule good { condition: true }")},
		{Name: "bad.yar", Text: []byte("rule {")},
	})
	if err == nil || !strings.Contains(err.Error(), "bad.yar") {
		t.Fatalf("err = %v, want one naming bad.yar", err)
	}
}

func TestLoadRulesRejectsGarbage(t *testing.T) {
	if _, err := LoadRules(strings.NewReader("not rules")); err == nil {
		t.Fatal("garbage must not load as rules")
	}
}

type ruleWriterFunc func([]byte) (int, error)

func (f ruleWriterFunc) Write(p []byte) (int, error) { return f(p) }

func TestRulesWriteToReportsPartialWrites(t *testing.T) {
	compiled, err := CompileSources([]Source{{Name: "test.yar", Text: []byte("rule test { condition: true }")}})
	if err != nil {
		t.Fatal(err)
	}
	writeErr := errors.New("write failed")
	for _, tc := range []struct {
		name    string
		written int
		err     error
		wantErr error
	}{
		{name: "failure", err: writeErr, wantErr: writeErr},
		{name: "partial failure", written: 7, err: writeErr, wantErr: writeErr},
		{name: "short write", written: 7, wantErr: io.ErrShortWrite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, err := compiled.WriteTo(ruleWriterFunc(func(p []byte) (int, error) {
				if len(p) <= tc.written {
					t.Fatalf("serialized rules too short: %d", len(p))
				}
				return tc.written, tc.err
			}))
			if n != int64(tc.written) || !errors.Is(err, tc.wantErr) {
				t.Fatalf("WriteTo = %d, %v; want %d, %v", n, err, tc.written, tc.wantErr)
			}
		})
	}
}
