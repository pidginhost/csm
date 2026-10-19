package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pidginhost/csm/internal/control"
)

// syncBuffer lets a fake daemon read what the CLI printed so far.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func asRoot(t *testing.T) {
	t.Helper()
	saved := antispamEUID
	antispamEUID = func() int { return 0 }
	t.Cleanup(func() { antispamEUID = saved })
}

func mailFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func learnResponse(t *testing.T, res control.AntispamLearnResult) control.Response {
	t.Helper()
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	return control.Response{OK: true, Result: data}
}

func TestLearnRequiresRoot(t *testing.T) {
	var requests atomic.Int32
	t.Cleanup(fakeDaemon(t, func(control.Request) control.Response {
		requests.Add(1)
		return control.Response{OK: true}
	}))
	saved := antispamEUID
	antispamEUID = func() int { return 1000 }
	t.Cleanup(func() { antispamEUID = saved })
	var out, errOut bytes.Buffer
	if code := antispamLearn([]string{"--spam", mailFile(t, "a.eml", "x")}, &out, &errOut); code == 0 || !strings.Contains(errOut.String(), "root") {
		t.Fatalf("code %d stderr %q", code, errOut.String())
	}
	if requests.Load() != 0 {
		t.Fatal("non-root run reached the daemon")
	}
}

func TestLearnRequiresOneAction(t *testing.T) {
	asRoot(t)
	file := mailFile(t, "a.eml", "x")
	for _, args := range [][]string{{}, {file}, {"--spam"}, {"--spam", "--forget", file}, {"--forget"}, {"--other", file}} {
		var out, errOut bytes.Buffer
		if code := antispamLearn(args, &out, &errOut); code == 0 {
			t.Errorf("%q accepted", args)
		}
	}
}

func TestLearnRejectsSymlinkAndLinkedFile(t *testing.T) {
	asRoot(t)
	var requests atomic.Int32
	t.Cleanup(fakeDaemon(t, func(control.Request) control.Response {
		requests.Add(1)
		return control.Response{OK: true}
	}))
	file := mailFile(t, "a.eml", "spam")
	link := filepath.Join(t.TempDir(), "link.eml")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	linked := mailFile(t, "b.eml", "spam")
	if err := os.Link(linked, linked+".2"); err != nil {
		t.Fatal(err)
	}
	big := mailFile(t, "big.eml", strings.Repeat("x", 10<<20+1))
	for _, p := range []string{link, linked, big, filepath.Dir(file), filepath.Join(t.TempDir(), "missing")} {
		var out, errOut bytes.Buffer
		if code := antispamLearn([]string{"--spam", p}, &out, &errOut); code == 0 || errOut.Len() == 0 {
			t.Errorf("%s accepted: code %d", p, code)
		}
	}
	if requests.Load() != 0 {
		t.Fatal("an unsafe file reached the daemon")
	}
}

func TestLearnPrintsRequestIDFirst(t *testing.T) {
	asRoot(t)
	out := &syncBuffer{}
	var printedFirst atomic.Bool
	var sent control.AntispamLearnArgs
	t.Cleanup(fakeDaemon(t, func(req control.Request) control.Response {
		_ = json.Unmarshal(req.Args, &sent)
		printedFirst.Store(sent.RequestID != "" && strings.Contains(out.String(), sent.RequestID))
		return learnResponse(t, control.AntispamLearnResult{RequestID: sent.RequestID, Outcome: "committed", ExitOK: true,
			Clusters: []control.AntispamLearnCluster{{ClusterID: 3, Result: "committed"}}})
	}))
	var errOut bytes.Buffer
	if code := antispamLearn([]string{"--spam", mailFile(t, "a.eml", "spam body")}, out, &errOut); code != 0 {
		t.Fatalf("code %d stderr %q", code, errOut.String())
	}
	if !printedFirst.Load() {
		t.Fatal("request ID was not printed before the request was sent")
	}
	if len(sent.RequestID) != 32 || sent.Name != "a.eml" || string(sent.Snapshot) != "spam body" || sent.Action != "spam" {
		t.Fatalf("sent %+v", sent)
	}
	if !strings.Contains(out.String(), "cluster 3: committed") {
		t.Fatalf("output %q", out.String())
	}
}

// Review focus 4: a reply lost in transport is retried once with the same
// request ID and snapshot, and the daemon's recorded outcome is shown.
func TestLearnRetrySameIDReturnsRecordedOutcome(t *testing.T) {
	asRoot(t)
	var mu sync.Mutex
	var seen []control.AntispamLearnArgs
	t.Cleanup(fakeDaemon(t, func(req control.Request) control.Response {
		var a control.AntispamLearnArgs
		_ = json.Unmarshal(req.Args, &a)
		mu.Lock()
		seen = append(seen, a)
		mu.Unlock()
		return learnResponse(t, control.AntispamLearnResult{RequestID: a.RequestID, Outcome: "committed", ExitOK: true,
			Clusters: []control.AntispamLearnCluster{{ClusterID: 3, Result: "committed"}}})
	}))
	saved := learnSend
	var calls atomic.Int32
	learnSend = func(args control.AntispamLearnArgs) (json.RawMessage, error) {
		raw, err := saved(args)
		if calls.Add(1) == 1 {
			return nil, errLearnTransport // the reply that never arrived
		}
		return raw, err
	}
	t.Cleanup(func() { learnSend = saved })
	var out, errOut bytes.Buffer
	if code := antispamLearn([]string{"--spam", mailFile(t, "a.eml", "spam body")}, &out, &errOut); code != 0 {
		t.Fatalf("code %d stderr %q", code, errOut.String())
	}
	if len(seen) != 2 || seen[0].RequestID != seen[1].RequestID || seen[0].SnapshotSHA != seen[1].SnapshotSHA {
		t.Fatalf("requests %+v", seen)
	}
}

func TestLearnExitCodes(t *testing.T) {
	asRoot(t)
	for name, tc := range map[string]struct {
		resp control.Response
		want int
	}{
		"committed": {learnResponse(t, control.AntispamLearnResult{Outcome: "committed", ExitOK: true}), 0},
		"duplicate": {learnResponse(t, control.AntispamLearnResult{Outcome: "duplicate", ExitOK: true}), 0},
		"forgotten": {learnResponse(t, control.AntispamLearnResult{Outcome: "forgotten", ExitOK: true}), 0},
		"no-match":  {learnResponse(t, control.AntispamLearnResult{Outcome: "no-match", ExitOK: true}), 0},
		"pending":   {learnResponse(t, control.AntispamLearnResult{Outcome: "pending"}), 1},
		"partial":   {learnResponse(t, control.AntispamLearnResult{Outcome: "partial"}), 1},
		"skipped":   {learnResponse(t, control.AntispamLearnResult{Outcome: "skipped"}), 1},
		"refused":   {control.Response{OK: false, Error: "antispam learning is not enabled"}, 1},
	} {
		t.Run(name, func(t *testing.T) {
			cleanup := fakeDaemon(t, func(control.Request) control.Response { return tc.resp })
			defer cleanup()
			var out, errOut bytes.Buffer
			if code := antispamLearn([]string{"--forget", mailFile(t, "a.eml", "x")}, &out, &errOut); code != tc.want {
				t.Fatalf("code %d, want %d (stderr %q)", code, tc.want, errOut.String())
			}
		})
	}
	// Files are handled independently: one failure fails the run.
	cleanup := fakeDaemon(t, func(control.Request) control.Response {
		return learnResponse(t, control.AntispamLearnResult{Outcome: "committed", ExitOK: true})
	})
	defer cleanup()
	var out, errOut bytes.Buffer
	if code := antispamLearn([]string{"--spam", mailFile(t, "a.eml", "x"), filepath.Join(t.TempDir(), "missing")}, &out, &errOut); code == 0 {
		t.Fatal("a missing file did not fail the run")
	}
	if !strings.Contains(out.String(), "committed") {
		t.Fatalf("the readable file was not sent: %q", out.String())
	}
}
