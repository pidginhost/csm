package attackcorpus

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/pidginhost/csm/internal/selftest"
)

// Load reads every <dir>/<category>/<name>/sample.json and decodes each file
// once to validate it. Hidden entries and top-level files are skipped, so a
// git checkout with a README loads as a corpus. A missing or unreadable dir is
// an error: a mistyped private corpus path must not pass as an empty corpus.
func Load(dir, half string) ([]Sample, error) {
	if half != "public" && half != "private" {
		return nil, fmt.Errorf("unknown corpus half %q", half)
	}
	categories, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var samples []Sample
	seen := map[string]string{}
	for _, c := range categories {
		if !c.IsDir() || strings.HasPrefix(c.Name(), ".") {
			continue
		}
		entries, err := os.ReadDir(filepath.Join(dir, c.Name()))
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".") {
				continue
			}
			rel := c.Name() + "/" + e.Name()
			s, err := loadSample(filepath.Join(dir, c.Name(), e.Name()), half)
			if err != nil {
				return nil, fmt.Errorf("sample %s: %w", rel, err)
			}
			if prev, dup := seen[s.Name]; dup {
				return nil, fmt.Errorf("sample %s: duplicate name, also in %s", rel, prev)
			}
			seen[s.Name] = rel
			samples = append(samples, s)
		}
	}
	return samples, nil
}

func loadSample(dir, half string) (Sample, error) {
	// #nosec G304 -- dir is a sample directory under the corpus root the caller chose.
	data, err := os.ReadFile(filepath.Join(dir, "sample.json"))
	if err != nil {
		return Sample{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s Sample
	if err := dec.Decode(&s); err != nil {
		return Sample{}, err
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return Sample{}, errors.New("trailing data after the manifest")
	}
	s.Dir, s.Half = dir, half
	if err := s.validate(); err != nil {
		return Sample{}, err
	}
	if s.Name != filepath.Base(dir) || s.Category != filepath.Base(filepath.Dir(dir)) {
		return Sample{}, fmt.Errorf("manifest %s/%s does not match its directory", s.Category, s.Name)
	}
	return s, nil
}

// Content returns the decoded bytes of one of the sample's files.
func (s Sample) Content(f File) ([]byte, error) {
	if f.Selftest != "" {
		for _, b := range selftest.Samples() {
			if b.Name == f.Selftest {
				return b.Content()
			}
		}
		return nil, fmt.Errorf("unknown selftest sample %q", f.Selftest)
	}
	// #nosec G304 -- B64 is checked to be a plain file name inside the sample dir.
	encoded, err := os.ReadFile(filepath.Join(s.Dir, f.B64))
	if err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", f.B64, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%s: empty content", f.B64)
	}
	return data, nil
}

// PublicDir is the public corpus root inside this package's source tree.
func PublicDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "testdata", "corpus")
}

// ValidateCoverage requires a malicious sample and a control in every
// category and, with requireSelftest, every self-test bundle sample referenced
// exactly once, so the bundle and the corpus cannot drift.
func ValidateCoverage(samples []Sample, requireSelftest bool) error {
	var errs []error
	for _, c := range Categories {
		var malicious, control bool
		for _, s := range samples {
			if s.Category == string(c) {
				malicious = malicious || s.Kind == "malicious"
				control = control || s.Kind == "control"
			}
		}
		if !malicious {
			errs = append(errs, fmt.Errorf("category %s has no malicious sample", c))
		}
		if !control {
			errs = append(errs, fmt.Errorf("category %s has no control sample", c))
		}
	}
	if requireSelftest {
		refs := map[string]int{}
		for _, s := range samples {
			for _, f := range s.Files {
				if f.Selftest != "" {
					refs[f.Selftest]++
				}
			}
		}
		for _, b := range selftest.Samples() {
			if n := refs[b.Name]; n != 1 {
				errs = append(errs, fmt.Errorf("selftest sample %s referenced %d times, want 1", b.Name, n))
			}
		}
	}
	return errors.Join(errs...)
}
