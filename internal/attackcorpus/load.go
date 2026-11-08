package attackcorpus

import (
	"bytes"
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/pidginhost/csm/internal/safepath"
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
	corpusDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	root, err := safepath.OpenDir(corpusDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	categories, err := readDir(root, ".")
	if err != nil {
		return nil, err
	}
	var samples []Sample
	seen := map[string]string{}
	for _, c := range categories {
		if strings.HasPrefix(c.Name(), ".") {
			continue
		}
		if c.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("category %q: symlinks are not allowed", c.Name())
		}
		if !c.IsDir() {
			continue
		}
		entries, err := readDir(root, c.Name())
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".") {
				continue
			}
			rel := c.Name() + "/" + e.Name()
			if !e.IsDir() {
				return nil, fmt.Errorf("sample %s: expected a directory, not a file or symlink", rel)
			}
			s, err := loadSample(root, corpusDir, rel, half)
			if err != nil {
				return nil, fmt.Errorf("sample %s: %w", rel, err)
			}
			if prev, dup := seen[s.Name]; dup {
				return nil, fmt.Errorf("sample %s: duplicate name, also in %s", rel, prev)
			}
			seen[s.Name] = rel
			s.Dir = filepath.Join(dir, c.Name(), e.Name())
			samples = append(samples, s)
		}
	}
	return samples, nil
}

func readDir(root *safepath.Dir, relative string) ([]os.DirEntry, error) {
	dir, err := root.Walk(relative)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	entries, err := dir.ReadDir()
	if err != nil {
		return nil, err
	}
	slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return entries, nil
}

func readRegularFile(dir *safepath.Dir, name string) ([]byte, error) {
	// safepath rejects symlinks and opens nonblocking, so a FIFO cannot stall a run.
	f, err := dir.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", name)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func loadSample(root *safepath.Dir, corpusDir, relative, half string) (Sample, error) {
	dir, err := root.Walk(relative)
	if err != nil {
		return Sample{}, err
	}
	defer func() { _ = dir.Close() }()
	data, err := readRegularFile(dir, "sample.json")
	if err != nil {
		return Sample{}, err
	}
	s, err := decodeManifest(data)
	if err != nil {
		return Sample{}, err
	}
	s.Half, s.corpusDir, s.relativeDir = half, corpusDir, relative
	if err := s.validate(dir); err != nil {
		return Sample{}, err
	}
	if s.Name != filepath.Base(relative) || s.Category != filepath.Base(filepath.Dir(relative)) {
		return Sample{}, fmt.Errorf("manifest %s/%s does not match its directory", s.Category, s.Name)
	}
	return s, nil
}

func decodeManifest(data []byte) (Sample, error) {
	// JSON v2 rejects duplicate names and case aliases. Parser errors can quote
	// input bytes, so only fixed diagnostics leave this boundary.
	dec := jsontext.NewDecoder(bytes.NewReader(data))
	if _, err := dec.ReadValue(); err != nil {
		return Sample{}, errors.New("invalid manifest JSON")
	}
	if _, err := dec.ReadValue(); err != io.EOF {
		return Sample{}, errors.New("trailing data after the manifest")
	}
	var s Sample
	if err := json.Unmarshal(data, &s, json.RejectUnknownMembers(true)); err != nil {
		return Sample{}, errors.New("invalid manifest: unknown field or wrong field type")
	}
	return s, nil
}

// Content returns the decoded bytes of a file listed in a loaded sample.
// Source directories and files must still be present without symlinks.
func (s Sample) Content(f File) ([]byte, error) {
	if !slices.Contains(s.Files, f) {
		return nil, errors.New("file is not in the loaded sample")
	}
	if s.corpusDir == "" {
		return nil, errors.New("sample has not been loaded")
	}
	root, err := safepath.OpenDir(s.corpusDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	dir, err := root.Walk(s.relativeDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	return content(dir, f)
}

func content(dir *safepath.Dir, f File) ([]byte, error) {
	if f.Selftest != "" {
		for _, b := range selftest.Samples() {
			if b.Name == f.Selftest {
				return b.Content()
			}
		}
		return nil, fmt.Errorf("unknown selftest sample %q", f.Selftest)
	}
	encoded, err := readRegularFile(dir, f.B64)
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
