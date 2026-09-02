package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// The exposure walker skipped .git and .svn as "expensive", so a repository
// checked out into a document root, which hands every visitor the site's
// source and frequently its credentials, was never detected and never
// patched. The walker now probes the repository's marker file without
// descending, and the classifier knows what it is.
func TestExposureWalkerProbesRepositoryMetadata(t *testing.T) {
	docroot := t.TempDir()
	for _, p := range []string{".git/HEAD", ".git/objects/ab/cdef", ".svn/wc.db", "index.php"} {
		full := filepath.Join(docroot, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out, complete := walkExposureCandidatesLimit(context.Background(), docroot, 4, 100)
	if !complete {
		t.Fatal("walk reported incomplete")
	}
	joined := strings.Join(out, "\n")
	for _, want := range []string{filepath.Join(docroot, ".git", "HEAD"), filepath.Join(docroot, ".svn", "wc.db")} {
		if !strings.Contains(joined, want) {
			t.Fatalf("walker did not surface %s; got %v", want, out)
		}
	}
	if strings.Contains(joined, "objects") {
		t.Fatalf("walker descended into the repository: %v", out)
	}
}

func TestClassifyExposedPathRepositoryMetadata(t *testing.T) {
	for _, p := range []string{"/home/a/public_html/.git/HEAD", "/home/a/public_html/.svn/wc.db", "/home/a/public_html/sub/.svn/entries"} {
		if got := classifyExposedPath(p); got != classRepoMetadata {
			t.Fatalf("%s classified as %v, want repository metadata", p, got)
		}
	}
	if got := classifyExposedPath("/home/a/public_html/HEAD"); got == classRepoMetadata {
		t.Fatal("a plain file named HEAD outside a repository directory classified as repository metadata")
	}
	if classRepoMetadata.severity() != alert.Critical {
		t.Fatalf("repository metadata severity = %s, want Critical (source and credentials)", classRepoMetadata.severity())
	}
	if classRepoMetadata.findingName() != "web_exposed_repo_metadata" {
		t.Fatalf("finding name = %s", classRepoMetadata.findingName())
	}
}

// Denying only HEAD leaves objects, config and refs downloadable; the patch
// denies the whole repository directory.
func TestVirtualPatchExposedFileDeniesWholeRepositoryDirectory(t *testing.T) {
	root := vpTestEnv(t)
	repo := filepath.Join(root, "public_html", ".git")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	head := filepath.Join(repo, "HEAD")
	if err := os.WriteFile(head, []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := VirtualPatchExposedFile(head)
	if !res.Success {
		t.Fatalf("patch failed: %+v", res)
	}
	got, err := os.ReadFile(filepath.Join(repo, ".htaccess"))
	if err != nil {
		t.Fatalf("no .htaccess written in the repository directory: %v", err)
	}
	if !strings.Contains(string(got), `<FilesMatch "^">`) || !strings.Contains(string(got), "Require all denied") {
		t.Fatalf("repository .htaccess does not deny the whole directory:\n%s", got)
	}
}
