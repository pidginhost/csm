package main

import (
	"errors"
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
	prevEnsureMap := ensureChallengeMapFile
	challengeConfSrc, challengeConfDest = srcPath, destPath
	ensureChallengeMapFile = func() error { return nil }
	t.Cleanup(func() {
		challengeConfSrc, challengeConfDest = prevSrc, prevDest
		ensureChallengeMapFile = prevEnsureMap
	})
	return srcPath, destPath
}

func TestChallengeMapPathsFollowsApacheDirectiveSyntax(t *testing.T) {
	tests := []struct {
		name string
		data string
		want []string
	}{
		{
			name: "case insensitive directive",
			data: "rewritemap csm_challenge txt:/var/lib/csm/stale.txt\n",
			want: []string{"/var/lib/csm/stale.txt"},
		},
		{
			name: "single quoted source",
			data: "RewriteMap csm_challenge 'txt:/var/lib/csm/stale.txt'\n",
			want: []string{"/var/lib/csm/stale.txt"},
		},
		{
			name: "quoted source with spaces",
			data: "RewriteMap csm_challenge \"txt:/var/lib/csm/stale map.txt\"\n",
			want: []string{"/var/lib/csm/stale map.txt"},
		},
		{
			name: "continued directive",
			data: "RewriteMap csm_challenge \\\n  'txt:/var/lib/csm/stale.txt'\n",
			want: []string{"/var/lib/csm/stale.txt"},
		},
		{
			name: "uncontinued separate lines",
			data: "RewriteMap\ncsm_challenge\ntxt:/var/lib/csm/stale.txt\n",
		},
		{
			name: "commented directive",
			data: "# rewritemap csm_challenge txt:/var/lib/csm/stale.txt\n",
		},
		{
			name: "different map",
			data: "RewriteMap operator_map txt:/var/lib/csm/stale.txt\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := challengeMapPaths([]byte(tt.data))
			if len(got) != len(tt.want) {
				t.Fatalf("paths = %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("paths[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestReconcileChallengeConfRewritesStaleMapPath(t *testing.T) {
	srcPath, destPath := useChallengeConfPaths(t)
	if err := os.WriteFile(srcPath, []byte(validChallengeConf()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destPath, []byte(staleChallengeConf), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(destPath)
	if err != nil {
		t.Fatal(err)
	}
	ensured := 0
	ensureChallengeMapFile = func() error {
		ensured++
		return nil
	}

	changed, err := prepareChallengeConf()
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !changed {
		t.Fatal("stale RewriteMap path was not reconciled")
	}
	if ensured != 1 {
		t.Fatalf("map ensure calls = %d, want 1", ensured)
	}
	got, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != validChallengeConf() {
		t.Fatalf("reconciled conf = %q, want shipped template", got)
	}
	after, err := os.Stat(destPath)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("reconciled conf was rewritten in place, want atomic replacement")
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

	ensured := 0
	ensureChallengeMapFile = func() error {
		ensured++
		return nil
	}
	changed, err := prepareChallengeConf()
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if changed {
		t.Fatal("conf with the correct map path must not be rewritten")
	}
	if ensured != 1 {
		t.Fatalf("map ensure calls = %d, want 1", ensured)
	}
	got, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != custom {
		t.Fatalf("operator content was modified: %q", got)
	}
}

func TestReconcileChallengeConfIgnoresMissingDest(t *testing.T) {
	srcPath, destPath := useChallengeConfPaths(t)
	if err := os.WriteFile(srcPath, []byte(validChallengeConf()), 0o644); err != nil {
		t.Fatal(err)
	}

	ensured := 0
	ensureChallengeMapFile = func() error {
		ensured++
		return nil
	}
	changed, err := prepareChallengeConf()
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if changed {
		t.Fatal("reconcile must not install the snippet where the installer never did")
	}
	if ensured != 1 {
		t.Fatalf("map ensure calls = %d, want 1", ensured)
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

	changed, err := prepareChallengeConf()
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if changed {
		t.Fatal("a conf without the RewriteMap directive must be left alone")
	}
	got, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatal(err)
	}
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

	changed, err := prepareChallengeConf()
	if err == nil {
		t.Fatal("stale source template must return an error")
	}
	if changed {
		t.Fatal("reconcile must refuse to deploy a template that is itself stale")
	}
	got, readErr := os.ReadFile(destPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != staleChallengeConf {
		t.Fatalf("dest was modified with a stale template: %q", got)
	}
}

func TestReconcileChallengeConfReportsMissingSource(t *testing.T) {
	_, destPath := useChallengeConfPaths(t)
	if err := os.WriteFile(destPath, []byte(staleChallengeConf), 0o644); err != nil {
		t.Fatal(err)
	}

	changed, err := prepareChallengeConf()
	if err == nil {
		t.Fatal("missing source template must return an error")
	}
	if changed {
		t.Fatal("reconcile reported a rewrite without a source template")
	}
	got, readErr := os.ReadFile(destPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != staleChallengeConf {
		t.Fatalf("dest changed after source read failure: %q", got)
	}
}

func TestReconcileChallengeConfDoesNotRewriteWhenMapEnsureFails(t *testing.T) {
	srcPath, destPath := useChallengeConfPaths(t)
	if err := os.WriteFile(srcPath, []byte(validChallengeConf()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destPath, []byte(staleChallengeConf), 0o644); err != nil {
		t.Fatal(err)
	}
	ensureChallengeMapFile = func() error { return errors.New("read-only runtime dir") }

	changed, err := prepareChallengeConf()
	if err == nil {
		t.Fatal("map ensure failure must return an error")
	}
	if changed {
		t.Fatal("reconcile reported a rewrite without a readable map")
	}
	got, readErr := os.ReadFile(destPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != staleChallengeConf {
		t.Fatalf("dest changed after map ensure failure: %q", got)
	}
}
