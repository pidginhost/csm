package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if out, err := exec.Command("git", "init", "-q", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	return root
}

func writeFixture(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCheckCoversEveryFixtureFormatAndLocation(t *testing.T) {
	for _, name := range []string{"internal/mail/testdata/message.H", "internal/mime/testdata/simple-H", "internal/config/testdata/settings.json", "internal/checks/testdata/job.crontab", "e2e/fixtures/mail message.eml", "scripts/testdata/record.log"} {
		t.Run(name, func(t *testing.T) {
			root := fixtureRepo(t)
			writeFixture(t, root, name, "client=8.8.4.4\n")
			var output bytes.Buffer
			if err := check(root, &output); err == nil {
				t.Fatal("disallowed fixture was accepted")
			}
			if !strings.Contains(output.String(), name+":1:") || !strings.Contains(output.String(), "non-documentation IPv4 literal") || strings.Contains(output.String(), "8.8.4.4") {
				t.Fatalf("missing location or leaked address: %s", &output)
			}
		})
	}
}

func TestCheckAcceptsDocumentationAddresses(t *testing.T) {
	root := fixtureRepo(t)
	writeFixture(t, root, "internal/testdata/mail", "192.0.2.4 198.51.100.5 203.0.113.6 999.888.777.666\n")
	var output bytes.Buffer
	if err := check(root, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "1 fixture file(s) checked") {
		t.Fatalf("missing nonzero scan count: %s", &output)
	}
}

func TestCheckSurfacesListingAndReadErrors(t *testing.T) {
	t.Run("not a repository", func(t *testing.T) {
		if err := check(t.TempDir(), new(bytes.Buffer)); err == nil {
			t.Fatal("failed git listing was accepted")
		}
	})
	t.Run("tracked missing fixture", func(t *testing.T) {
		root := fixtureRepo(t)
		name := "internal/testdata/mail"
		writeFixture(t, root, name, "192.0.2.1\n")
		if out, err := exec.Command("git", "-C", root, "add", name).CombinedOutput(); err != nil {
			t.Fatalf("git add: %v: %s", err, out)
		}
		if err := os.Remove(filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
		if err := check(root, new(bytes.Buffer)); err == nil {
			t.Fatal("missing tracked fixture was accepted")
		}
	})
	t.Run("oversized line", func(t *testing.T) {
		root := fixtureRepo(t)
		writeFixture(t, root, "testdata/record", strings.Repeat("x", 2<<20)+"8.8.4.4\n")
		if err := check(root, new(bytes.Buffer)); err == nil {
			t.Fatal("scanner limit was treated as clean")
		}
	})
}

func TestCheckRejectsFixtureSymlinks(t *testing.T) {
	root := fixtureRepo(t)
	writeFixture(t, root, "private/source", "8.8.4.4\n")
	if err := os.Mkdir(filepath.Join(root, "testdata"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../private/source", filepath.Join(root, "testdata", "linked")); err != nil {
		t.Fatal(err)
	}
	if err := check(root, new(bytes.Buffer)); err == nil {
		t.Fatal("fixture symlink was accepted")
	}
}

func TestCheckRejectsEmptyFixtureSelection(t *testing.T) {
	root := fixtureRepo(t)
	writeFixture(t, root, "README.md", "192.0.2.1\n")
	if err := check(root, new(bytes.Buffer)); err == nil {
		t.Fatal("empty fixture selection was accepted")
	}
}
