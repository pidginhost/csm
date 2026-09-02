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

// listenUnix starts a fake clamd that answers PING, the way discovery now
// requires before it will hand mail to a socket.
func listenUnix(t *testing.T, path string) {
	t.Helper()
	listenUnixSpeaking(t, path, true)
}

// listenUnixSpeaking optionally answers PING, so a test can stand up something
// that merely accepts connections without speaking clamd.
func listenUnixSpeaking(t *testing.T, path string, clamd bool) {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 32)
				if _, err := c.Read(buf); err != nil {
					return
				}
				if clamd {
					_, _ = c.Write([]byte("PONG\x00"))
				}
			}()
		}
	}()
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

// Discovery hands every mail attachment to whatever it finds. Something that
// merely accepts a connection is not clamd: a fake that answers "OK" to every
// scan would suppress every finding, so the candidate has to speak the
// protocol before it is trusted with mail.
func TestResolveClamdSocketRejectsANonClamdListener(t *testing.T) {
	dir := shortTempDir(t)
	configured := filepath.Join(dir, "absent.sock")
	impostor := filepath.Join(dir, "impostor.sock")
	listenUnixSpeaking(t, impostor, false)

	withClamdCandidates(t, []string{impostor})

	got, discovered := ResolveClamdSocket(configured)
	if discovered || got != configured {
		t.Fatalf("ResolveClamdSocket = %q, %v; a listener that does not answer PING must be refused", got, discovered)
	}
}

// A candidate in a directory any account can write to is a socket any account
// can provide.
func TestResolveClamdSocketRejectsAWorldWritableDirectory(t *testing.T) {
	dir := shortTempDir(t)
	shared := filepath.Join(dir, "shared")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(shared, "clamd.sock")
	listenUnix(t, live)
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}

	withClamdCandidates(t, []string{live})

	configured := filepath.Join(dir, "absent.sock")
	got, discovered := ResolveClamdSocket(configured)
	if discovered || got != configured {
		t.Fatalf("ResolveClamdSocket = %q, %v; a socket under a world-writable directory must be refused", got, discovered)
	}
}

// /tmp is world-writable, so it must not be a candidate at all.
func TestClamdCandidatesExcludeWorldWritableLocations(t *testing.T) {
	for _, candidate := range clamdSocketCandidates {
		if strings.HasPrefix(candidate, "/tmp/") || strings.HasPrefix(candidate, "/var/tmp/") {
			t.Errorf("candidate %q is in a world-writable directory", candidate)
		}
	}
}

// The operator's own setting is still honoured as-is: it is a root-only file,
// and second-guessing it would break a deliberate non-standard deployment.
func TestResolveClamdSocketDoesNotSecondGuessTheConfiguredPath(t *testing.T) {
	dir := shortTempDir(t)
	shared := filepath.Join(dir, "shared")
	if err := os.Mkdir(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	configured := filepath.Join(shared, "clamd.sock")
	listenUnix(t, configured)

	withClamdCandidates(t, nil)

	if got, discovered := ResolveClamdSocket(configured); got != configured || discovered {
		t.Fatalf("ResolveClamdSocket = %q, %v; want the configured path kept", got, discovered)
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
