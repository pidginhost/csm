package attackcorpus

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/selftest"
)

const caseName = "case_sample"

func TestLoadParsesSample(t *testing.T) {
	dir := filepath.Join("testdata", "unit")
	samples, err := Load(dir, "public")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(samples) != 1 {
		t.Fatalf("loaded %d samples, want 1", len(samples))
	}
	got := samples[0]
	corpusDir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}

	note := File{Path: "public_html/note.php", B64: "note.b64", Mode: 0o644}
	htaccess := File{Path: "public_html/.htaccess", Selftest: "benign_htaccess"}
	want := Sample{
		Name:        "loader_fixture",
		Category:    "webshell",
		Kind:        "malicious",
		Source:      "synthetic",
		Description: "Harmless text standing in for a sample in the loader test.",
		Provenance:  "internal/attackcorpus/load_test.go",
		Files:       []File{note, htaccess},
		Expect: map[Path]PathExpect{
			Realtime: {
				Findings:    []ExpectedFinding{{Check: "test_check", File: note.Path, MinSeverity: "High"}},
				Remediation: map[string]Remediation{note.Path: Quarantined},
			},
			Tier: {Gap: "fixture records a gap on this path"},
			FullScan: {
				Findings:      []ExpectedFinding{{Check: "test_check", File: note.Path, MinSeverity: "critical"}},
				Remediation:   map[string]Remediation{note.Path: Cleaned, htaccess.Path: Untouched},
				CleanedSHA256: map[string]string{note.Path: "37c3dee866bc87fc3d52b6b053805dfbe5df3d394fdad9ec535f162a4e695941"},
			},
		},
		Dir:         filepath.Join(dir, "webshell", "loader_fixture"),
		Half:        "public",
		corpusDir:   corpusDir,
		relativeDir: "webshell/loader_fixture",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed sample:\n got %+v\nwant %+v", got, want)
	}

	content, err := got.Content(note)
	if err != nil {
		t.Fatalf("Content(b64): %v", err)
	}
	if string(content) != "harmless loader fixture text\n" {
		t.Error("Content(b64) differs from the fixture")
	}

	content, err = got.Content(htaccess)
	if err != nil {
		t.Fatalf("Content(selftest): %v", err)
	}
	var bundle []byte
	for _, b := range selftest.Samples() {
		if b.Name == htaccess.Selftest {
			if bundle, err = b.Content(); err != nil {
				t.Fatalf("bundle content: %v", err)
			}
		}
	}
	if len(bundle) == 0 || !bytes.Equal(content, bundle) {
		t.Error("Content(selftest) differs from the bundle")
	}
}

func TestLoadRejectsUnsafePaths(t *testing.T) {
	for _, p := range []string{"../x", "/etc/x", "a/../../x", "", "a//b", "@other", ".", "a/"} {
		t.Run(p, func(t *testing.T) {
			s := maliciousSample()
			s.Files[0].Path = p
			wantErr(t, loadOne(t, s), caseName, "unsafe path")
		})
	}

	t.Run("crontab twice", func(t *testing.T) {
		s := maliciousSample()
		s.Files = append(s.Files, File{Path: "@crontab", B64: "a.b64"}, File{Path: "@crontab", B64: "a.b64"})
		wantErr(t, loadOne(t, s), caseName, "duplicate path")
	})

	t.Run("crontab once", func(t *testing.T) {
		s := maliciousSample()
		s.Files = append(s.Files, File{Path: "@crontab", B64: "a.b64"})
		root := t.TempDir()
		writeSample(t, filepath.Join(root, s.Category, s.Name), s)
		got, err := Load(root, "public")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if len(got) != 1 || len(got[0].Files) != 2 || got[0].Files[1].Path != "@crontab" {
			t.Fatalf("loaded %+v, want one sample with @crontab as its second file", got)
		}
	})
}

func TestLoadRejectsBadManifests(t *testing.T) {
	setExpect := func(s *Sample, p Path, edit func(*PathExpect)) {
		e := s.Expect[p]
		edit(&e)
		s.Expect[p] = e
	}
	cases := []struct {
		name   string
		base   func() Sample
		mutate func(*Sample)
		raw    func([]byte) []byte
		want   string
	}{
		{name: "unknown category", mutate: func(s *Sample) { s.Category = "bogus" }, want: "unknown category"},
		{name: "category differs from directory", mutate: func(s *Sample) { s.Category = string(Dropper) }, want: "does not match its directory"},
		{name: "name differs from directory", mutate: func(s *Sample) { s.Name = "other" }, want: "does not match its directory"},
		{name: "unknown kind", mutate: func(s *Sample) { s.Kind = "suspicious" }, want: "unknown kind"},
		{name: "unknown source", mutate: func(s *Sample) { s.Source = "internet" }, want: "unknown source"},
		{name: "no files", mutate: func(s *Sample) { s.Files = nil }, want: "no files"},
		{name: "gap with findings", mutate: func(s *Sample) {
			setExpect(s, Tier, func(e *PathExpect) { e.Gap = "misses it" })
		}, want: "exclusive"},
		{name: "malicious without findings or gap", mutate: func(s *Sample) {
			setExpect(s, FullScan, func(e *PathExpect) { e.Findings = nil })
		}, want: "findings or a gap"},
		{name: "control with gap", base: controlSample, mutate: func(s *Sample) {
			setExpect(s, Realtime, func(e *PathExpect) { e.Gap = "misses it" })
		}, want: "control expects no"},
		{name: "control with finding", base: controlSample, mutate: func(s *Sample) {
			setExpect(s, Realtime, func(e *PathExpect) { e.Findings = findings() })
		}, want: "control expects no"},
		{name: "control quarantined", base: controlSample, mutate: func(s *Sample) {
			setExpect(s, FullScan, func(e *PathExpect) { e.Remediation = map[string]Remediation{"public_html/a.php": Quarantined} })
		}, want: "control leaves"},
		{name: "remediation for unknown file", mutate: func(s *Sample) {
			setExpect(s, FullScan, func(e *PathExpect) { e.Remediation = map[string]Remediation{"public_html/b.php": Quarantined} })
		}, want: "not in files"},
		{name: "removed remediation", mutate: func(s *Sample) {
			setExpect(s, FullScan, func(e *PathExpect) { e.Remediation = map[string]Remediation{"public_html/a.php": Removed} })
		}, want: `remediation "removed"`},
		{name: "unknown remediation", mutate: func(s *Sample) {
			setExpect(s, FullScan, func(e *PathExpect) { e.Remediation = map[string]Remediation{"public_html/a.php": "deleted"} })
		}, want: `remediation "deleted"`},
		{name: "cleaned without sha256", mutate: func(s *Sample) {
			setExpect(s, FullScan, func(e *PathExpect) { e.Remediation = map[string]Remediation{"public_html/a.php": Cleaned} })
		}, want: "no valid cleaned_sha256"},
		{name: "cleaned with malformed sha256", mutate: func(s *Sample) {
			setExpect(s, FullScan, func(e *PathExpect) {
				e.Remediation = map[string]Remediation{"public_html/a.php": Cleaned}
				e.CleanedSHA256 = map[string]string{"public_html/a.php": strings.Repeat("A", 64)}
			})
		}, want: "no valid cleaned_sha256"},
		{name: "sha256 for a file not cleaned", mutate: func(s *Sample) {
			setExpect(s, FullScan, func(e *PathExpect) {
				e.CleanedSHA256 = map[string]string{"public_html/a.php": strings.Repeat("a", 64)}
			})
		}, want: "which is not cleaned"},
		{name: "both b64 and selftest", mutate: func(s *Sample) { s.Files[0].Selftest = "benign_htaccess" }, want: "exactly one"},
		{name: "neither b64 nor selftest", mutate: func(s *Sample) { s.Files[0].B64 = "" }, want: "exactly one"},
		{name: "unknown selftest name", mutate: func(s *Sample) {
			s.Files[0] = File{Path: s.Files[0].Path, Selftest: "no_such_sample"}
		}, want: "unknown selftest sample"},
		{name: "b64 outside the sample directory", mutate: func(s *Sample) { s.Files[0].B64 = "../a.b64" }, want: "beside the manifest"},
		{name: "missing b64 file", mutate: func(s *Sample) { s.Files[0].B64 = "missing.b64" }, want: "missing.b64"},
		{name: "undecodable base64", mutate: func(s *Sample) { s.Files[0].B64 = "bad.b64" }, want: "illegal base64"},
		{name: "empty base64", mutate: func(s *Sample) { s.Files[0].B64 = "empty.b64" }, want: "empty content"},
		{name: "mode beyond permission bits", mutate: func(s *Sample) { s.Files[0].Mode = 0o4755 }, want: "beyond the permission bits"},
		{name: "unknown severity", mutate: func(s *Sample) {
			setExpect(s, Realtime, func(e *PathExpect) { e.Findings[0].MinSeverity = "severe" })
		}, want: "unknown severity"},
		{name: "finding without check", mutate: func(s *Sample) {
			setExpect(s, Realtime, func(e *PathExpect) { e.Findings[0].Check = "" })
		}, want: "no check"},
		{name: "finding for unknown file", mutate: func(s *Sample) {
			setExpect(s, Realtime, func(e *PathExpect) { e.Findings[0].File = "public_html/b.php" })
		}, want: "not in files"},
		{name: "missing realtime expect", mutate: func(s *Sample) { delete(s.Expect, Realtime) }, want: "missing expect for realtime"},
		{name: "missing tier expect", mutate: func(s *Sample) { delete(s.Expect, Tier) }, want: "missing expect for tier"},
		{name: "missing fullscan expect", mutate: func(s *Sample) { delete(s.Expect, FullScan) }, want: "missing expect for fullscan"},
		{name: "unknown expect path", mutate: func(s *Sample) { s.Expect["yara"] = PathExpect{Findings: findings()} }, want: "unknown path"},
		{name: "unknown field", raw: func(b []byte) []byte {
			return bytes.Replace(b, []byte("{"), []byte(`{"severity":"high",`), 1)
		}, want: "unknown field"},
		{name: "trailing data", raw: func(b []byte) []byte { return append(b, []byte("{}")...) }, want: "trailing data"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := maliciousSample
			if tc.base != nil {
				base = tc.base
			}
			s := base()
			root := t.TempDir()
			dir := filepath.Join(root, s.Category, s.Name)
			if tc.mutate != nil {
				tc.mutate(&s)
			}
			manifest, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			if tc.raw != nil {
				manifest = tc.raw(manifest)
			}
			writeManifest(t, dir, manifest)
			_, err = Load(root, "public")
			wantErr(t, err, caseName, tc.want)
		})
	}

	t.Run("duplicate sample names", func(t *testing.T) {
		root := t.TempDir()
		a := maliciousSample()
		b := maliciousSample()
		b.Category = string(Dropper)
		writeSample(t, filepath.Join(root, a.Category, a.Name), a)
		writeSample(t, filepath.Join(root, b.Category, b.Name), b)
		_, err := Load(root, "public")
		wantErr(t, err, caseName, "duplicate name")
	})
}

func TestLoadDirectory(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing"), "private"); err == nil {
		t.Error("Load of a missing directory returned no error")
	}

	samples, err := Load(t.TempDir(), "private")
	if err != nil || len(samples) != 0 {
		t.Errorf("Load of an empty directory = %d samples, %v; want 0, nil", len(samples), err)
	}
	if ValidateCoverage(samples, false) == nil {
		t.Error("ValidateCoverage passed an empty corpus")
	}

	if _, err = Load(t.TempDir(), "both"); err == nil || !strings.Contains(err.Error(), "half") {
		t.Errorf("Load with an unknown half = %v, want an error naming the half", err)
	}

	root := t.TempDir()
	s := controlSample()
	writeSample(t, filepath.Join(root, s.Category, s.Name), s)
	for _, extra := range []string{".git/objects", ".hidden"} {
		if err = os.MkdirAll(filepath.Join(root, extra), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, extra := range []string{"README.md", filepath.Join(s.Category, ".DS_Store")} {
		if err = os.WriteFile(filepath.Join(root, extra), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	samples, err = Load(root, "private")
	if err != nil || len(samples) != 1 || samples[0].Half != "private" {
		t.Errorf("Load beside hidden entries and a top-level file = %+v, %v; want the one sample, half private", samples, err)
	}
}

func TestValidateCoverage(t *testing.T) {
	complete := func() []Sample {
		var out []Sample
		for _, c := range Categories {
			out = append(out,
				Sample{Name: string(c) + "_m", Category: string(c), Kind: "malicious"},
				Sample{Name: string(c) + "_c", Category: string(c), Kind: "control"})
		}
		return out
	}
	withBundle := func(samples []Sample) []Sample {
		for _, b := range selftest.Samples() {
			samples[0].Files = append(samples[0].Files, File{Path: b.Name, Selftest: b.Name})
		}
		return samples
	}
	bundle := selftest.Samples()
	if len(bundle) == 0 {
		t.Fatal("selftest bundle is empty")
	}

	if err := ValidateCoverage(complete(), false); err != nil {
		t.Errorf("complete corpus without bundle refs, requireSelftest=false: %v", err)
	}
	if err := ValidateCoverage(withBundle(complete()), true); err != nil {
		t.Errorf("complete corpus with each bundle sample once: %v", err)
	}

	// One bundle sample referenced zero times, and one referenced twice.
	missing := withBundle(complete())
	missing[0].Files = missing[0].Files[1:]
	twice := withBundle(complete())
	twice[1].Files = []File{{Path: "again", Selftest: bundle[0].Name}}

	cases := []struct {
		name    string
		samples []Sample
		want    string
	}{
		{name: "empty", samples: nil, want: "category webshell has no malicious sample"},
		{name: "no malicious", samples: withBundle(drop(complete(), string(Archive)+"_m")), want: "category archive has no malicious sample"},
		{name: "no control", samples: withBundle(drop(complete(), string(Persistence)+"_c")), want: "category persistence has no control sample"},
		{name: "bundle sample unreferenced", samples: missing, want: "selftest sample " + bundle[0].Name + " referenced 0 times"},
		{name: "bundle sample twice", samples: twice, want: "selftest sample " + bundle[0].Name + " referenced 2 times"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantErr(t, ValidateCoverage(tc.samples, true), tc.want)
		})
	}

	if err := ValidateCoverage(missing, false); err != nil {
		t.Errorf("bundle refs are not checked when requireSelftest=false, got %v", err)
	}
}

func TestPublicDir(t *testing.T) {
	dir := PublicDir()
	if !filepath.IsAbs(dir) || !strings.HasSuffix(dir, filepath.Join("internal", "attackcorpus", "testdata", "corpus")) {
		t.Fatalf("PublicDir() = %q", dir)
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "..", "load_test.go")); err != nil {
		t.Errorf("PublicDir() is not next to the package source: %v", err)
	}
}

// The corpus gate runs only in its own CI job, so a broken manifest must
// fail the normal suite first.
func TestPublicCorpusLoads(t *testing.T) {
	samples, err := Load(PublicDir(), "public")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(samples) == 0 {
		t.Fatal("public corpus has no samples")
	}
}

func findings() []ExpectedFinding {
	return []ExpectedFinding{{Check: "test_check", File: "public_html/a.php", MinSeverity: "high"}}
}

func maliciousSample() Sample {
	return Sample{
		Name:        caseName,
		Category:    string(Webshell),
		Kind:        "malicious",
		Source:      "synthetic",
		Description: "loader test case",
		Files:       []File{{Path: "public_html/a.php", B64: "a.b64"}},
		Expect: map[Path]PathExpect{
			Realtime: {Findings: findings()},
			Tier:     {Findings: findings()},
			FullScan: {Findings: findings()},
		},
	}
}

func controlSample() Sample {
	s := maliciousSample()
	s.Kind = "control"
	s.Expect = map[Path]PathExpect{Realtime: {}, Tier: {}, FullScan: {}}
	return s
}

func drop(samples []Sample, name string) []Sample {
	var out []Sample
	for _, s := range samples {
		if s.Name != name {
			out = append(out, s)
		}
	}
	return out
}

func loadOne(t *testing.T, s Sample) error {
	t.Helper()
	root := t.TempDir()
	writeSample(t, filepath.Join(root, s.Category, s.Name), s)
	_, err := Load(root, "public")
	return err
}

func writeSample(t *testing.T, dir string, s Sample) {
	t.Helper()
	manifest, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	writeManifest(t, dir, manifest)
}

// writeManifest writes the manifest plus the base64 files the cases point at:
// a.b64 decodes to harmless text, bad.b64 is not base64, empty.b64 is empty.
func writeManifest(t *testing.T, dir string, manifest []byte) {
	t.Helper()
	files := map[string]string{
		"sample.json": string(manifest),
		"a.b64":       "aGFybWxlc3MgdGVzdCB0ZXh0Cg==\n",
		"bad.b64":     "not base64 at all!\n",
		"empty.b64":   "",
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func wantErr(t *testing.T, err error, wants ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("got no error, want one containing %q", wants)
	}
	for _, want := range wants {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	}
}
