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
			if err := check(root, nil, &output); err == nil {
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
	if err := check(root, nil, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "1 fixture file(s) checked") {
		t.Fatalf("missing nonzero scan count: %s", &output)
	}
}

func TestCheckSurfacesListingAndReadErrors(t *testing.T) {
	t.Run("not a repository", func(t *testing.T) {
		if err := check(t.TempDir(), nil, new(bytes.Buffer)); err == nil {
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
		if err := check(root, nil, new(bytes.Buffer)); err == nil {
			t.Fatal("missing tracked fixture was accepted")
		}
	})
	t.Run("oversized line", func(t *testing.T) {
		root := fixtureRepo(t)
		writeFixture(t, root, "testdata/record", strings.Repeat("x", 2<<20)+"8.8.4.4\n")
		if err := check(root, nil, new(bytes.Buffer)); err == nil {
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
	if err := check(root, nil, new(bytes.Buffer)); err == nil {
		t.Fatal("fixture symlink was accepted")
	}
}

func TestCheckRejectsEmptyFixtureSelection(t *testing.T) {
	root := fixtureRepo(t)
	writeFixture(t, root, "README.md", "192.0.2.1\n")
	if err := check(root, nil, new(bytes.Buffer)); err == nil {
		t.Fatal("empty fixture selection was accepted")
	}
}

func writeTerms(t *testing.T, lines string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "terms")
	if err := os.WriteFile(path, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckRejectsPrivateTermsInAnyRepositoryFile(t *testing.T) {
	for _, name := range []string{"internal/checks/example_test.go", "cmd/csm/main.go", "docs/src/guide.md", "ROADMAP.md", "scripts/tool/anonymize.go"} {
		t.Run(name, func(t *testing.T) {
			root := fixtureRepo(t)
			writeFixture(t, root, "internal/testdata/mail", "192.0.2.4\n")
			writeFixture(t, root, name, "clean line\n// first seen on HostSeven\n")
			terms, err := loadTerms(writeTerms(t, "# private names\n\nhostseven\n"))
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			if err := check(root, terms, &output); err == nil {
				t.Fatal("private term was accepted")
			}
			if !strings.Contains(output.String(), name+":2: private term") || strings.Contains(strings.ToLower(output.String()), "hostseven") {
				t.Fatalf("missing location or leaked term: %s", &output)
			}
		})
	}
}

func TestCheckAcceptsRepositoryWithoutPrivateTerms(t *testing.T) {
	root := fixtureRepo(t)
	writeFixture(t, root, "internal/testdata/mail", "192.0.2.4\n")
	writeFixture(t, root, "internal/checks/example_test.go", "// the example host\n")
	terms, err := loadTerms(writeTerms(t, "hostseven\n"))
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := check(root, terms, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "2 file(s) scanned for private terms") {
		t.Fatalf("missing term scan count: %s", &output)
	}
}

func TestCheckWithoutTermsReportsTheSkippedScan(t *testing.T) {
	root := fixtureRepo(t)
	writeFixture(t, root, "internal/testdata/mail", "192.0.2.4\n")
	var output bytes.Buffer
	if err := check(root, nil, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "private-term scan skipped") {
		t.Fatalf("missing skip notice: %s", &output)
	}
}

func TestCheckSkipsSymlinksOutsideFixtureDirectories(t *testing.T) {
	root := fixtureRepo(t)
	writeFixture(t, root, "internal/testdata/mail", "192.0.2.4\n")
	writeFixture(t, root, "private/source", "HostSeven\n")
	if err := os.Symlink("private/source", filepath.Join(root, "linked.md")); err != nil {
		t.Fatal(err)
	}
	terms, err := loadTerms(writeTerms(t, "hostseven\n"))
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := check(root, terms, &output); err == nil {
		t.Fatal("the symlink target holds the term and must be reported through its real path")
	}
	if !strings.Contains(output.String(), "private/source:1: private term") || strings.Contains(output.String(), "linked.md") {
		t.Fatalf("expected only the real file to be reported: %s", &output)
	}
}

func TestLoadTerms(t *testing.T) {
	t.Run("ignores comments and blank lines", func(t *testing.T) {
		terms, err := loadTerms(writeTerms(t, "# comment\n\nalpha\n  beta  \n"))
		if err != nil {
			t.Fatal(err)
		}
		if len(terms) != 2 || !terms[0].MatchString("ALPHA") || !terms[1].MatchString("Beta") {
			t.Fatalf("terms = %v", terms)
		}
	})
	t.Run("rejects an invalid pattern", func(t *testing.T) {
		if _, err := loadTerms(writeTerms(t, "valid\n(unclosed\n")); err == nil {
			t.Fatal("invalid pattern was accepted")
		}
	})
	t.Run("rejects an empty file", func(t *testing.T) {
		if _, err := loadTerms(writeTerms(t, "# nothing\n")); err == nil {
			t.Fatal("empty terms file was accepted")
		}
	})
	t.Run("missing file", func(t *testing.T) {
		if _, err := loadTerms(filepath.Join(t.TempDir(), "absent")); err == nil {
			t.Fatal("missing terms file was accepted")
		}
	})
}

func TestTermsSourceRequiresAFileWhenAsked(t *testing.T) {
	if _, err := termsSource("", true); err == nil {
		t.Fatal("missing terms file was accepted although required")
	}
	terms, err := termsSource("", false)
	if err != nil || terms != nil {
		t.Fatalf("optional missing terms = %v, %v", terms, err)
	}
}
