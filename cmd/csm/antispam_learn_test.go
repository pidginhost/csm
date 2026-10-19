package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/control"
)

// syncBuffer lets a fake daemon read what the CLI printed so far.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func TestLearnRejectsSymlinkAncestor(t *testing.T) {
	file := mailFile(t, "a.eml", "spam")
	link := filepath.Join(t.TempDir(), "mail")
	if err := os.Symlink(filepath.Dir(file), link); err != nil {
		t.Fatal(err)
	}
	if _, err := readLearnFile(filepath.Join(link, "a.eml")); err == nil {
		t.Fatal("followed a symlink ancestor")
	}
}

func TestLearnRejectsChangesDuringRead(t *testing.T) {
	for _, change := range []string{"restored mtime", "new link", "unlinked"} {
		t.Run(change, func(t *testing.T) {
			file := mailFile(t, "a.eml", "original")
			before, err := os.Stat(file)
			if err != nil {
				t.Fatal(err)
			}
			saved := learnReadAll
			learnReadAll = func(r io.Reader) ([]byte, error) {
				data, err := io.ReadAll(r)
				if err != nil {
					return nil, err
				}
				switch change {
				case "restored mtime":
					if err := os.WriteFile(file, []byte("modified"), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Chtimes(file, before.ModTime(), before.ModTime()); err != nil {
						t.Fatal(err)
					}
				case "new link":
					if err := os.Link(file, file+".link"); err != nil {
						t.Fatal(err)
					}
				case "unlinked":
					if err := os.Remove(file); err != nil {
						t.Fatal(err)
					}
				}
				return data, nil
			}
			t.Cleanup(func() { learnReadAll = saved })
			if _, err := readLearnFile(file); err == nil {
				t.Fatal("accepted a changed snapshot")
			}
		})
	}
}

type failedLearnOutput struct{}

func (failedLearnOutput) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestLearnDoesNotSendWithoutPrintedID(t *testing.T) {
	asRoot(t)
	saved := learnSend
	calls := 0
	learnSend = func(control.AntispamLearnArgs) (json.RawMessage, error) {
		calls++
		return json.RawMessage(`{"exit_ok":true}`), nil
	}
	t.Cleanup(func() { learnSend = saved })
	var errOut bytes.Buffer
	code := antispamLearn([]string{"--spam", mailFile(t, "a.eml", "spam")}, failedLearnOutput{}, &errOut)
	if code == 0 || calls != 0 || errOut.Len() == 0 {
		t.Fatalf("code %d, requests %d, stderr %q", code, calls, errOut.String())
	}
}

func TestLearnReplyRetryClassification(t *testing.T) {
	for _, tc := range []struct {
		name, reply string
		calls, code int
	}{
		{"truncated", `{"ok":true,"result":`, 2, 0},
		{"malformed line", "{\n", 1, 1},
		{"empty line", "\n", 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asRoot(t)
			file := mailFile(t, "a.eml", "spam")
			listener, err := net.Listen("unix", shortSockPath(t))
			if err != nil {
				t.Fatal(err)
			}
			saved := controlSocketPath
			controlSocketPath = listener.Addr().String()
			done := make(chan []control.AntispamLearnArgs, 1)
			go func() {
				var seen []control.AntispamLearnArgs
				defer func() { done <- seen }()
				for i := 0; i < 2; i++ {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
					var req control.Request
					if err := json.NewDecoder(conn).Decode(&req); err != nil {
						t.Error(err)
						_ = conn.Close()
						return
					}
					var args control.AntispamLearnArgs
					if err := json.Unmarshal(req.Args, &args); err != nil {
						t.Error(err)
					}
					seen = append(seen, args)
					if i == 0 {
						if err := os.WriteFile(file, []byte("changed after submission"), 0600); err != nil {
							t.Error(err)
						}
						_, _ = io.WriteString(conn, tc.reply)
					} else {
						_ = json.NewEncoder(conn).Encode(learnResponse(t, control.AntispamLearnResult{RequestID: args.RequestID, Outcome: "committed", ExitOK: true}))
					}
					_ = conn.Close()
				}
			}()
			t.Cleanup(func() { controlSocketPath = saved })
			var out, errOut bytes.Buffer
			code := antispamLearn([]string{"--spam", file}, &out, &errOut)
			_ = listener.Close()
			seen := <-done
			if code != tc.code || len(seen) != tc.calls {
				t.Fatalf("code %d, requests %d, stderr %q", code, len(seen), errOut.String())
			}
			if len(seen) == 2 && (seen[0].RequestID != seen[1].RequestID || seen[0].SnapshotSHA != seen[1].SnapshotSHA || !bytes.Equal(seen[0].Snapshot, seen[1].Snapshot)) {
				t.Fatal("transport retry changed the request")
			}
		})
	}
}

func TestLearnDoesNotRetryDefiniteFailure(t *testing.T) {
	asRoot(t)
	for _, reply := range []control.Response{
		{OK: false, Error: "learning disabled"},
		learnResponse(t, control.AntispamLearnResult{Outcome: "pending"}),
	} {
		var calls atomic.Int32
		cleanup := fakeDaemon(t, func(control.Request) control.Response { calls.Add(1); return reply })
		var out, errOut bytes.Buffer
		code := antispamLearn([]string{"--spam", mailFile(t, "a.eml", "spam")}, &out, &errOut)
		cleanup()
		if code == 0 || calls.Load() != 1 {
			t.Fatalf("code %d, requests %d", code, calls.Load())
		}
	}
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
