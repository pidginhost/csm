package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestVerifyRejectsMissingSkippedAndFailedRequiredTests(t *testing.T) {
	inventory := []testID{{Package: "pkg", Name: "TestRequired"}}
	for _, tc := range []struct {
		name, events string
		wantErr      bool
	}{
		{"pass", `{"Package":"pkg","Test":"TestRequired","Action":"pass"}` + "\n" + `{"Package":"pkg","Action":"pass"}`, false},
		{"empty", "", true},
		{"skip", `{"Package":"pkg","Test":"TestRequired","Action":"skip"}` + "\n" + `{"Package":"pkg","Action":"pass"}`, true},
		{"failed", `{"Package":"pkg","Test":"TestRequired","Action":"fail"}` + "\n" + `{"Package":"pkg","Action":"fail"}`, true},
		{"package_missing", `{"Package":"pkg","Test":"TestRequired","Action":"pass"}`, true},
		{"invalid", "not JSON", true},
		{"unselected", `{"Package":"different","Test":"TestRequired","Action":"pass"}` + "\n" + `{"Package":"different","Action":"pass"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verify(inventory, inventory, strings.NewReader(tc.events))
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestVerifyRequiresEverySelectedTest(t *testing.T) {
	events := `{"Package":"pkg","Test":"TestFirst","Action":"pass"}` + "\n" + `{"Package":"pkg","Action":"pass"}`
	inventory := []testID{{Package: "pkg", Name: "TestFirst"}, {Package: "pkg", Name: "TestNew"}}
	if err := verify(inventory, nil, strings.NewReader(events)); err == nil {
		t.Fatal("new test omitted from execution was accepted")
	}
}

func TestInventoryTracksBuildTagsAndNewPackages(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	files := map[string]string{
		"go.mod":                    "module example.test/inventory\n\ngo 1.26.7\n",
		"first/normal_test.go":      "package first\nimport \"testing\"\nfunc TestNormal(t *testing.T) {}\nfunc TestMain(m *testing.M) { m.Run() }\n",
		"first/tagged_test.go":      "//go:build bpf && journal\n\npackage first\nimport \"testing\"\nfunc TestTagged(t *testing.T) {}\n",
		"newpackage/tagged_test.go": "//go:build yara\n\npackage newpackage\nimport \"testing\"\nfunc TestNewTagged(t *testing.T) {}\n",
	}
	for name, content := range files {
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	selected, err := inventory("yara,journal,bpf", ".", []string{"./..."})
	if err != nil {
		t.Fatal(err)
	}
	want := []testID{{Package: "example.test/inventory/first", Name: "TestNormal", Source: "normal_test.go"}, {Package: "example.test/inventory/first", Name: "TestTagged", Source: "tagged_test.go"}, {Package: "example.test/inventory/newpackage", Name: "TestNewTagged", Source: "tagged_test.go"}}
	if !reflect.DeepEqual(selected, want) {
		t.Fatalf("selected=%+v want=%+v", selected, want)
	}
	selected, err = inventory("", ".", []string{"./..."})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(selected, want[:1]) {
		t.Fatalf("untagged inventory = %+v", selected)
	}
}

func TestAdditionalTagsSelectNewPackagesAndArbitraryTestNames(t *testing.T) {
	ordinary := testID{Package: "pkg", Name: "TestOrdinary"}
	attachment := testID{Package: "pkg", Name: "TestAttachment"}
	added := testID{Package: "newpkg", Name: "TestDelivery"}
	selected, err := additionalTests([]testID{ordinary, attachment, added}, []testID{ordinary, attachment}, []testID{attachment})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(selected, []testID{attachment, added}) {
		t.Fatalf("selected=%+v", selected)
	}
	swapped := ordinary
	swapped.Source = "kernel_test.go"
	selected, err = additionalTests([]testID{swapped}, []testID{ordinary}, nil)
	if err != nil || !reflect.DeepEqual(selected, []testID{swapped}) {
		t.Fatalf("a different tagged file reused the test name: selected=%+v err=%v", selected, err)
	}
	if _, err := additionalTests([]testID{ordinary}, nil, []testID{attachment}); err == nil {
		t.Fatal("missing required test was accepted")
	}
}
