// testgate records selected tests and verifies that go test executed them.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

type testID struct {
	Package string
	Name    string
	Source  string `json:",omitempty"`
}

type listedPackage struct {
	ImportPath   string
	Dir          string
	TestGoFiles  []string
	XTestGoFiles []string
}

func inventory(tags, pattern string, packages []string) ([]testID, error) {
	selected, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	args := append([]string{"list", "-json", "-tags", tags}, packages...)
	cmd := exec.Command("go", args...)
	cmd.Stderr = os.Stderr
	data, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	var tests []testID
	for {
		var pkg listedPackage
		if err := decoder.Decode(&pkg); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		for _, name := range append(pkg.TestGoFiles, pkg.XTestGoFiles...) {
			parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join(pkg.Dir, name), nil, 0)
			if err != nil {
				return nil, err
			}
			for _, declaration := range parsed.Decls {
				fn, ok := declaration.(*ast.FuncDecl)
				if !ok || fn.Recv != nil || fn.Name.Name == "TestMain" || !strings.HasPrefix(fn.Name.Name, "Test") {
					continue
				}
				suffix := []rune(strings.TrimPrefix(fn.Name.Name, "Test"))
				if len(suffix) > 0 && unicode.IsLower(suffix[0]) {
					continue
				}
				if selected.MatchString(fn.Name.Name) {
					tests = append(tests, testID{Package: pkg.ImportPath, Name: fn.Name.Name, Source: name})
				}
			}
		}
	}
	if len(tests) == 0 {
		return nil, errors.New("no tests selected")
	}
	sort.Slice(tests, func(i, j int) bool {
		if tests[i].Package != tests[j].Package {
			return tests[i].Package < tests[j].Package
		}
		return tests[i].Name < tests[j].Name
	})
	return tests, nil
}

func (test testID) key() testID { test.Source = ""; return test }

func additionalTests(selected, baseline, required []testID) ([]testID, error) {
	old := make(map[testID]bool)
	present := make(map[testID]bool)
	mustRun := make(map[testID]bool)
	for _, test := range baseline {
		old[test] = true
	}
	for _, test := range selected {
		present[test.key()] = true
	}
	for _, test := range required {
		if !present[test.key()] {
			return nil, fmt.Errorf("required test was not selected: %+v", test)
		}
		mustRun[test.key()] = true
	}
	var result []testID
	for _, test := range selected {
		if !old[test] || mustRun[test.key()] {
			result = append(result, test)
		}
	}
	if len(result) == 0 {
		return nil, errors.New("no additional tests selected")
	}
	return result, nil
}

func verify(selected, required []testID, events io.Reader) error {
	if len(selected) == 0 {
		return errors.New("empty inventory")
	}
	results := make(map[testID]string)
	packages := make(map[string]bool)
	decoder := json.NewDecoder(events)
	for {
		var event struct{ Package, Test, Action string }
		if err := decoder.Decode(&event); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("test output: %w", err)
		}
		if event.Action == "fail" {
			return fmt.Errorf("test failure: %s %s", event.Package, event.Test)
		}
		if event.Action != "pass" && event.Action != "skip" {
			continue
		}
		if event.Test == "" {
			packages[event.Package] = event.Action == "pass"
		} else {
			results[testID{Package: event.Package, Name: event.Test}] = event.Action
		}
	}
	for _, test := range selected {
		if !packages[test.Package] || results[test.key()] == "" {
			return fmt.Errorf("selected test was not completed: %+v", test)
		}
	}
	for _, test := range required {
		if !packages[test.Package] || results[test.key()] != "pass" {
			return fmt.Errorf("required test did not pass: %+v (%s)", test, results[test.key()])
		}
	}
	return nil
}

func run() error {
	baseTags := flag.String("base-tags", "", "select tests added to these baseline tags")
	patternFile := flag.String("pattern-file", "", "write an exact test-name expression")
	tags := flag.String("tags", "yara,journal,bpf", "build tags")
	pattern := flag.String("run", ".", "selected top-level test expression")
	output := flag.String("inventory", "", "inventory JSON path")
	events := flag.String("events", "", "verify an existing go test JSON stream")
	requiredPath := flag.String("required", "", "required test JSON path")
	flag.Parse()
	if *output == "" {
		return errors.New("-inventory is required")
	}
	if *events == "" {
		selected, err := inventory(*tags, *pattern, flag.Args())
		if err != nil {
			return err
		}

		if *baseTags != "" {
			baseline, baselineErr := inventory(*baseTags, *pattern, flag.Args())
			if baselineErr != nil {
				return baselineErr
			}
			data, readErr := os.ReadFile(*requiredPath)
			if readErr != nil {
				return readErr
			}
			var required []testID
			if decodeErr := json.Unmarshal(data, &required); decodeErr != nil {
				return decodeErr
			}
			selected, err = additionalTests(selected, baseline, required)
			if err != nil {
				return err
			}
		}
		if *patternFile != "" {
			names := make([]string, 0, len(selected))
			for _, test := range selected {
				names = append(names, regexp.QuoteMeta(test.Name))
			}
			if writeErr := os.WriteFile(*patternFile, []byte("^("+strings.Join(names, "|")+")$\n"), 0o600); writeErr != nil {
				return writeErr
			}
		}
		data, err := json.MarshalIndent(selected, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(*output, append(data, '\n'), 0o600)
	}
	var selected, required []testID
	for name, dest := range map[string]*[]testID{*output: &selected, *requiredPath: &required} {
		if name == "" {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, dest); err != nil {
			return err
		}
	}
	file, err := os.Open(*events)
	if err != nil {
		return err
	}
	defer file.Close()
	return verify(selected, required, file)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
