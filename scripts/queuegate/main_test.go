package main

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func cliFixture(t *testing.T) (string, queueManifest) {
	t.Helper()
	fixture, manifest := manifestFixture(t)
	root := t.TempDir()
	if err := fs.WalkDir(fixture, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		dest := filepath.Join(root, filepath.FromSlash(name))
		if entry.IsDir() {
			return os.MkdirAll(dest, 0o700)
		}
		data, err := fs.ReadFile(fixture, name)
		if err != nil {
			return err
		}
		return os.WriteFile(dest, data, 0o600)
	}); err != nil {
		t.Fatal(err)
	}
	writeFixtureJSON(t, filepath.Join(root, "manifest.json"), manifest)
	writeFixtureJSON(t, filepath.Join(root, "baseline.json"), []requiredTest{{Package: modulePath + "/internal/example", Name: "TestBaseline"}})
	return root, manifest
}

func writeFixtureJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCLIValidatesInventoryBeforeWritingRequirements(t *testing.T) {
	root, manifest := cliFixture(t)
	output := filepath.Join(root, "required.json")
	args := []string{"-root", root, "-manifest", "manifest.json", "-base-required", "baseline.json", "-required-out", output}
	var stdout bytes.Buffer
	if err := run(args, &stdout); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var required []requiredTest
	if decodeErr := json.Unmarshal(data, &required); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	var names []string
	for _, test := range required {
		names = append(names, test.Name)
	}
	if !slices.Equal(names, []string{"TestBaseline", "TestLifecycle", "TestPublished"}) {
		t.Fatalf("required output=%s", data)
	}
	manifest.Allocations[0].Capacity = "999"
	writeFixtureJSON(t, filepath.Join(root, "manifest.json"), manifest)
	if runErr := run(args, &stdout); runErr == nil || !strings.Contains(runErr.Error(), "allocation changed") {
		t.Fatalf("changed allocation: %v", runErr)
	}
	after, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, after) {
		t.Fatal("failed validation overwrote requirements")
	}
}

func TestCLIScanOnlyProducesUnclassifiedAllocations(t *testing.T) {
	root, _ := cliFixture(t)
	var stdout bytes.Buffer
	if err := run([]string{"-root", root, "-scan"}, &stdout); err != nil {
		t.Fatal(err)
	}
	var sites []allocation
	if err := json.Unmarshal(stdout.Bytes(), &sites); err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 || sites[0].Capacity != "4" {
		t.Fatalf("scan=%s", stdout.Bytes())
	}
	if err := run([]string{"-root", root, "-scan", "-required-out", filepath.Join(root, "invalid.json")}, &stdout); err == nil {
		t.Fatal("scan-only created execution requirements")
	}
}

func TestCLIRejectsMalformedAndAmbiguousManifests(t *testing.T) {
	for _, tc := range []struct{ name, suffix, reason string }{
		{"extra value", " {}", "multiple JSON values"},
		{"unknown field", `,"ignored":true}`, "unknown field"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, _ := cliFixture(t)
			file := filepath.Join(root, "manifest.json")
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "unknown field" {
				data = data[:len(data)-1]
			}
			data = append(data, tc.suffix...)
			if writeErr := os.WriteFile(file, data, 0o600); writeErr != nil {
				t.Fatal(writeErr)
			}
			var stdout bytes.Buffer
			err = run([]string{"-root", root, "-manifest", "manifest.json"}, &stdout)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("err=%v want %q", err, tc.reason)
			}
			if stdout.Len() != 0 {
				t.Fatalf("invalid input produced output %q", stdout.String())
			}
		})
	}
}
