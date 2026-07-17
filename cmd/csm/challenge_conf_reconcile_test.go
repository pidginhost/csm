package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/challenge"
)

const staleChallengeConf = `# CSM Challenge Page - Apache Configuration
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteMap csm_challenge "txt:/var/lib/csm/state/challenge_ips.txt"
  RewriteCond ${csm_challenge:%{REMOTE_ADDR}} =challenge
  RewriteRule ^(.*)$ http://127.0.0.1:8439/challenge?dest=%{REQUEST_SCHEME}://%{HTTP_HOST}$1 [P,L]
</IfModule>
`

func validChallengeConf() string {
	return `# CSM Challenge Page - Apache Configuration
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteMap csm_challenge "txt:` + challenge.DefaultMapPath + `"
  RewriteCond ${csm_challenge:%{REMOTE_ADDR}} =challenge
  RewriteRule ^(.*)$ http://127.0.0.1:8439/challenge?dest=%{REQUEST_SCHEME}://%{HTTP_HOST}$1 [P,L]
</IfModule>
`
}

func useChallengeConfPaths(t *testing.T) (srcPath, destPath string) {
	t.Helper()
	dir := t.TempDir()
	srcPath = filepath.Join(dir, "src", "csm_challenge.conf")
	destPath = filepath.Join(dir, "dest", "csm_challenge.conf")
	if err := os.MkdirAll(filepath.Dir(srcPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		t.Fatal(err)
	}
	prevSrc, prevDest := challengeConfSrc, challengeConfDest
	challengeConfSrc, challengeConfDest = srcPath, destPath
	t.Cleanup(func() { challengeConfSrc, challengeConfDest = prevSrc, prevDest })
	return srcPath, destPath
}

func TestReconcileChallengeConfRewritesStaleMapPath(t *testing.T) {
	srcPath, destPath := useChallengeConfPaths(t)
	if err := os.WriteFile(srcPath, []byte(validChallengeConf()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destPath, []byte(staleChallengeConf), 0o644); err != nil {
		t.Fatal(err)
	}

	if !reconcileChallengeConf() {
		t.Fatal("stale RewriteMap path was not reconciled")
	}
	got, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != validChallengeConf() {
		t.Fatalf("reconciled conf = %q, want shipped template", got)
	}
}

func TestReconcileChallengeConfLeavesCorrectPathAlone(t *testing.T) {
	srcPath, destPath := useChallengeConfPaths(t)
	if err := os.WriteFile(srcPath, []byte(validChallengeConf()), 0o644); err != nil {
		t.Fatal(err)
	}
	// Operator-customized body whose map path is already the one the daemon
	// maintains: content differs from the template but is not broken.
	custom := "# operator notes\n" + validChallengeConf()
	if err := os.WriteFile(destPath, []byte(custom), 0o644); err != nil {
		t.Fatal(err)
	}

	if reconcileChallengeConf() {
		t.Fatal("conf with the correct map path must not be rewritten")
	}
	got, _ := os.ReadFile(destPath)
	if string(got) != custom {
		t.Fatalf("operator content was modified: %q", got)
	}
}

func TestReconcileChallengeConfIgnoresMissingDest(t *testing.T) {
	srcPath, destPath := useChallengeConfPaths(t)
	if err := os.WriteFile(srcPath, []byte(validChallengeConf()), 0o644); err != nil {
		t.Fatal(err)
	}

	if reconcileChallengeConf() {
		t.Fatal("reconcile must not install the snippet where the installer never did")
	}
	if _, err := os.Stat(destPath); !os.IsNotExist(err) {
		t.Fatalf("dest was created: %v", err)
	}
}

func TestReconcileChallengeConfIgnoresFileWithoutDirective(t *testing.T) {
	srcPath, destPath := useChallengeConfPaths(t)
	if err := os.WriteFile(srcPath, []byte(validChallengeConf()), 0o644); err != nil {
		t.Fatal(err)
	}
	gutted := "# operator disabled the challenge glue\n"
	if err := os.WriteFile(destPath, []byte(gutted), 0o644); err != nil {
		t.Fatal(err)
	}

	if reconcileChallengeConf() {
		t.Fatal("a conf without the RewriteMap directive must be left alone")
	}
	got, _ := os.ReadFile(destPath)
	if string(got) != gutted {
		t.Fatalf("gutted conf was modified: %q", got)
	}
}

func TestReconcileChallengeConfRefusesStaleSourceTemplate(t *testing.T) {
	srcPath, destPath := useChallengeConfPaths(t)
	// Both the installed conf and the shipped template are stale: rewriting
	// would just re-install the broken path, so nothing may change.
	if err := os.WriteFile(srcPath, []byte(staleChallengeConf), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destPath, []byte(staleChallengeConf), 0o644); err != nil {
		t.Fatal(err)
	}

	if reconcileChallengeConf() {
		t.Fatal("reconcile must refuse to deploy a template that is itself stale")
	}
	got, _ := os.ReadFile(destPath)
	if string(got) != staleChallengeConf {
		t.Fatalf("dest was modified with a stale template: %q", got)
	}
}
