package modsec

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type ruleReadFunc func([]byte) (int, error)

func (read ruleReadFunc) Read(p []byte) (int, error) { return read(p) }

type ruleReadCloser struct {
	io.Reader
	io.Closer
}

func interceptRuleReads(t *testing.T, path string, wrap func(*os.File) io.Reader) {
	t.Helper()
	previous := openRuleFile
	t.Cleanup(func() { openRuleFile = previous })
	openRuleFile = func(name string) (io.ReadCloser, error) {
		if name != path {
			return previous(name)
		}
		f, err := os.Open(name)
		if err != nil {
			return nil, err
		}
		return ruleReadCloser{Reader: wrap(f), Closer: f}, nil
	}
}

// A read can fail once and succeed when retried by the drain. Those bytes
// still cannot describe a cacheable build: the parser abandoned this file.
func TestBuildRegistryDoesNotCacheTransientReadFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prefix int
	}{
		{"before_data", 0},
		{"with_partial_data", 12},
		{"with_all_data", 4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeRule(t, filepath.Join(dir, "good.conf"), `SecRule ARGS "@rx x" "id:1,deny"`)
			path := filepath.Join(dir, "transient.conf")
			writeRule(t, path, `SecRule ARGS "@rx y" "id:2,pass"`)
			readErr := errors.New("transient rule read failure")
			fail := true
			interceptRuleReads(t, path, func(f *os.File) io.Reader {
				return ruleReadFunc(func(p []byte) (int, error) {
					if fail {
						fail = false
						n := 0
						if tc.prefix > 0 {
							var err error
							n, err = f.Read(p[:min(tc.prefix, len(p))])
							if err != nil {
								return n, err
							}
						}
						return n, readErr
					}
					return f.Read(p)
				})
			})

			reg, err := BuildRegistry([]string{dir})
			if !errors.Is(err, readErr) {
				t.Fatalf("BuildRegistry error = %v, want %v", err, readErr)
			}
			if reg.Fingerprint() != "" {
				t.Error("a transient read failure left an incomplete registry cacheable")
			}
			if action, ok := reg.Action(1); !ok || action != "deny" {
				t.Fatalf("unaffected rule lost: action=%q known=%v", action, ok)
			}

			reg, err = BuildRegistry([]string{dir})
			if err != nil {
				t.Fatal(err)
			}
			if action, ok := reg.Action(2); !ok || action != "pass" {
				t.Fatalf("retry lost recovered rule: action=%q known=%v", action, ok)
			}
			fingerprint, _ := RuleTreeFingerprint([]string{dir})
			if reg.Fingerprint() == "" || reg.Fingerprint() != fingerprint {
				t.Fatal("recovered build does not match the complete tree fingerprint")
			}
		})
	}
}

// Appending after the parser's EOF must change the next fingerprint, not
// become part of a cached fingerprint whose registry never saw the append.
func TestBuildRegistryDoesNotHashAppendsAfterParserEOF(t *testing.T) {
	for _, body := range []string{"", `SecRule ARGS "@rx x" "id:1,deny"` + "\n"} {
		name := "populated"
		if body == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "vendor.conf")
			writeRule(t, path, body)
			before, _ := RuleTreeFingerprint([]string{dir})
			appended := false
			interceptRuleReads(t, path, func(f *os.File) io.Reader {
				return ruleReadFunc(func(p []byte) (int, error) {
					n, err := f.Read(p)
					if err == io.EOF && !appended {
						appended = true
						out, openErr := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
						if openErr != nil {
							t.Fatal(openErr)
						}
						_, writeErr := io.WriteString(out, `SecRule ARGS "@rx y" "id:2,pass"`+"\n")
						if closeErr := errors.Join(writeErr, out.Close()); closeErr != nil {
							t.Fatal(closeErr)
						}
					}
					return n, err
				})
			})

			reg, err := BuildRegistry([]string{dir})
			if err != nil {
				t.Fatal(err)
			}
			if !appended {
				t.Fatal("the parser did not reach EOF")
			}
			if _, known := reg.Action(2); known {
				t.Fatal("rule appended after EOF was unexpectedly parsed")
			}
			if reg.Fingerprint() != before {
				t.Error("registry fingerprint includes bytes appended after the parser's EOF")
			}
			after, _ := RuleTreeFingerprint([]string{dir})
			if reg.Fingerprint() == after {
				t.Fatal("append would not trigger a rebuild for the missing rule")
			}
		})
	}
}
