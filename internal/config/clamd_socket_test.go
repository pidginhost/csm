package config

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withClamdCandidates replaces the candidate list for one test.
func withClamdCandidates(t *testing.T, candidates []string) {
	t.Helper()
	previous := clamdSocketCandidates
	clamdSocketCandidates = candidates
	t.Cleanup(func() { clamdSocketCandidates = previous })
}

// shortTempDir keeps socket paths inside the ~104 byte sun_path limit.
// t.TempDir() embeds the test name, which these names alone would overrun.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "csmav")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func listenUnix(t *testing.T, path string) {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
}

// The configured path is authoritative whenever something is actually
// listening on it.
func TestResolveClamdSocketPrefersTheConfiguredPath(t *testing.T) {
	dir := shortTempDir(t)
	configured := filepath.Join(dir, "configured.sock")
	other := filepath.Join(dir, "other.sock")
	listenUnix(t, configured)
	listenUnix(t, other)

	withClamdCandidates(t, []string{other})

	got, discovered := ResolveClamdSocket(configured)
	if got != configured {
		t.Fatalf("socket = %q, want the configured path", got)
	}
	if discovered {
		t.Fatal("a working configured socket must not be reported as discovered")
	}
}

// The shipped default names the RHEL clamd-scan socket. A cPanel host runs
// cPanel's own clamd on a different path, so a host that never had the
// setting corrected scanned no mail at all while reporting a healthy watcher.
func TestResolveClamdSocketFallsBackToAListeningCandidate(t *testing.T) {
	dir := shortTempDir(t)
	missing := filepath.Join(dir, "absent.sock")
	live := filepath.Join(dir, "live.sock")
	listenUnix(t, live)

	withClamdCandidates(t, []string{filepath.Join(dir, "nothing-here.sock"), live})

	got, discovered := ResolveClamdSocket(missing)
	if got != live {
		t.Fatalf("socket = %q, want the listening candidate %q", got, live)
	}
	if !discovered {
		t.Fatal("a fallback must be reported as discovered so validate can say so")
	}
}

// With nothing listening anywhere the configured path is kept, so the error
// the operator sees names what they configured rather than a path they have
// never heard of.
func TestResolveClamdSocketKeepsConfiguredWhenNothingListens(t *testing.T) {
	dir := shortTempDir(t)
	configured := filepath.Join(dir, "absent.sock")

	withClamdCandidates(t, []string{filepath.Join(dir, "also-absent.sock")})

	got, discovered := ResolveClamdSocket(configured)
	if got != configured {
		t.Fatalf("socket = %q, want the configured path", got)
	}
	if discovered {
		t.Fatal("nothing was discovered")
	}
}

func TestResolveClamdSocketEmptyConfigStillDiscovers(t *testing.T) {
	dir := shortTempDir(t)
	live := filepath.Join(dir, "live.sock")
	listenUnix(t, live)

	withClamdCandidates(t, []string{live})

	if got, discovered := ResolveClamdSocket(""); got != live || !discovered {
		t.Fatalf("ResolveClamdSocket(\"\") = %q, %v; want %q, true", got, discovered, live)
	}
}

// A host that has been corrected must not be nagged, and one that has not
// must be told both paths.
func TestProbeClamdNamesTheDiscoveredSocket(t *testing.T) {
	dir := shortTempDir(t)
	configured := filepath.Join(dir, "absent.sock")
	live := filepath.Join(dir, "live.sock")
	listenUnix(t, live)

	withClamdCandidates(t, []string{live})

	res := probeClamd(configured)
	if len(res) != 1 {
		t.Fatalf("results = %d, want 1: %+v", len(res), res)
	}
	if res[0].Level != "warn" {
		t.Fatalf("level = %q, want warn", res[0].Level)
	}
	for _, want := range []string{configured, live} {
		if !strings.Contains(res[0].Message, want) {
			t.Errorf("message %q must name %q", res[0].Message, want)
		}
	}
}
