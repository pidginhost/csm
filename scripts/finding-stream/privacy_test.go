package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/processctx"
)

func TestAnonymizerDoesNotTrustPseudonymPrefixes(t *testing.T) {
	for _, raw := range []string{"host-alice.example.com", "acct-alice.example.net", "user-carol.example.org", "dom-alice.example.com"} {
		t.Run(raw, func(t *testing.T) {
			a := NewAnonymizer(testSalt())
			if got := a.Text(raw); strings.Contains(got, raw) {
				t.Fatalf("domain escaped replacement: %q", got)
			}
			if got := a.Verify([]alert.AuditEvent{{Details: raw}}); len(got) == 0 {
				t.Fatal("independent leak check accepted raw domain")
			}
		})
	}
}

func TestAnonymizerRejectsDisguisedLearnedNames(t *testing.T) {
	a := NewAnonymizer(testSalt())
	for _, raw := range []string{"alice", "acct-abcdef", "alice.bob"} {
		a.Learn([]alert.AuditEvent{{TenantID: raw}})
		if got := a.Verify([]alert.AuditEvent{{Details: raw}}); len(got) == 0 {
			t.Errorf("raw account %q hidden by pseudonym masking", raw)
		}
		if got := a.Text("backup-" + raw + ".log"); strings.Contains(got, raw) {
			t.Errorf("embedded account %q survived: %q", raw, got)
		}
	}
}

func TestAnonymizerLearnsProcessTextAndScrubsComm(t *testing.T) {
	e := alert.AuditEvent{Process: &processctx.ProcessContext{
		Comm: "alice", Exe: "/home/alice/bin/task", Cmdline: []string{"task", "alice", "carol@example.com"},
		Parent: &processctx.ProcessContext{Cmdline: []string{"/home/bob/bin/task", "bob"}},
	}}
	a := NewAnonymizer(testSalt())
	a.Learn([]alert.AuditEvent{e})
	got := a.Event(e)
	for _, raw := range []string{"alice", "bob", "example.com"} {
		if strings.Contains(eventText(got), raw) {
			t.Errorf("process identity %q survived: %s", raw, eventText(got))
		}
	}
	if problems := a.Verify([]alert.AuditEvent{got}); len(problems) != 0 {
		t.Fatalf("scrubbed process failed verification: %v", problems)
	}
}

func TestAnonymizerScrubsMixedIPv6AndPreservesLoopback(t *testing.T) {
	a := NewAnonymizer(testSalt())
	raw := "::ffff:203.0.113.9"
	if got := a.Text("[" + raw + "]:443"); got != "["+a.IPv6(raw)+"]:443" {
		t.Errorf("mixed address not replaced as a unit: %q", got)
	}
	if got := a.Text("127.0.0.1 ::1"); got != "127.0.0.1 ::1" {
		t.Errorf("loopback changed: %q", got)
	}
	if problems := a.Verify([]alert.AuditEvent{{Details: "address:" + raw}}); len(problems) == 0 {
		t.Fatal("colon-prefixed mixed address escaped independent verification")
	}
	for _, addr := range []string{"2001:db8::7", raw} {
		if got := a.Text(addr + "."); got != a.IPv6(addr)+"." {
			t.Errorf("address at sentence end not scrubbed: %q", got)
		}
		if got := a.Text("address:" + addr); got != "address:"+a.IPv6(addr) {
			t.Errorf("colon-prefixed address not scrubbed: %q", got)
		}
	}
}

func TestAnonymizerScrubsAddressesInFilenames(t *testing.T) {
	a := NewAnonymizer(testSalt())
	for _, raw := range []string{"203.0.113.9.log", "client.203.0.113.9", "client4.203.0.113.9", "203.0.113.9.0log", "203.0.113.9.20260909.log", "203.0.113.9.1.log", "client4.203.0.113.9.1.log"} {
		if got := a.Text(raw); strings.Contains(got, "203.0.113.9") {
			t.Errorf("address survived in filename: %q", got)
		}
		if got := a.Verify([]alert.AuditEvent{{Details: raw}}); len(got) == 0 {
			t.Errorf("address in filename escaped verification: %q", raw)
		}
		if problems := a.Verify([]alert.AuditEvent{{Details: a.Text(raw)}}); len(problems) != 0 {
			t.Errorf("generated address suffix misclassified: %v", problems)
		}
	}
}

func TestVerifyIncludesPreservedMetadata(t *testing.T) {
	a := NewAnonymizer(testSalt())
	a.Learn([]alert.AuditEvent{{TenantID: "alice"}})
	if got := a.Verify([]alert.AuditEvent{{FindingID: "alice"}}); len(got) == 0 {
		t.Error("raw finding id escaped leak check")
	}
}

// Check names and severities are vocabulary, not identities: a hosting
// account called "abuse" does not turn every xmlrpc_abuse row into a leak,
// while the same word in free text is still replaced and still verified.
func TestVerifyIgnoresAccountNamesInsideCheckNames(t *testing.T) {
	a := NewAnonymizer(testSalt())
	e := alert.AuditEvent{Check: "xmlrpc_abuse", Severity: "HIGH", TenantID: "abuse", Message: "XML-RPC abuse from 203.0.113.9 against abuse"}
	a.Learn([]alert.AuditEvent{e})
	got := a.Event(e)
	if got.Check != "xmlrpc_abuse" || strings.Contains(got.Message, "abuse") {
		t.Fatalf("check name rewritten or message kept the account: %+v", got)
	}
	if problems := a.Verify([]alert.AuditEvent{got}); len(problems) != 0 {
		t.Fatalf("check name reported as a leak: %v", problems)
	}
	if problems := a.Verify([]alert.AuditEvent{e}); len(problems) == 0 {
		t.Fatal("raw account in message not reported")
	}
}

func TestAnonymizerRedactsQuotedSecrets(t *testing.T) {
	a := NewAnonymizer(testSalt())
	for _, text := range []string{`password="alice bob"`, `{"secret": "alice bob"}`, "token='alice bob'", `password="alice bob`, `password="alice bob\`, "token='alice bob\\"} {
		if got := a.Text(text); strings.Contains(got, "alice") || strings.Contains(got, "bob") || !strings.Contains(got, "[redacted]") {
			t.Errorf("quoted credential survived: %q", got)
		}
	}
}

func TestAnonymizerScrubsUnlearnedDomainInFilename(t *testing.T) {
	a := NewAnonymizer(testSalt())
	for _, raw := range []string{"example.com.log", "example.net-ssl_log"} {
		if got := a.Text(raw); strings.Contains(got, "example.com") || strings.Contains(got, "example.net") {
			t.Errorf("unlearned domain survived in filename: %q", got)
		}
		if got := a.Verify([]alert.AuditEvent{{Details: raw}}); len(got) == 0 {
			t.Errorf("unlearned embedded domain escaped verification: %q", raw)
		}
	}
}

func TestSaltRejectsPublicPermissionsAndSymlinks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "salt")
	if _, err := loadOrCreateSalt(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateSalt(path); err == nil {
		t.Error("accepted publicly readable salt")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := path + "-link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateSalt(link); err == nil {
		t.Error("accepted a symlink salt")
	}
}

func TestConcurrentSaltCreationNeverReplacesKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "salt")
	start := make(chan struct{})
	results := make(chan []byte, 16)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			<-start
			salt, err := loadOrCreateSalt(path)
			if err == nil {
				results <- salt
			} else if !strings.Contains(err.Error(), "shorter than 32 bytes") {
				t.Errorf("unexpected creation failure: %v", err)
			}
		})
	}
	close(start)
	wg.Wait()
	close(results)
	stored, err := loadOrCreateSalt(path)
	if err != nil {
		t.Fatal(err)
	}
	successes := 0
	for salt := range results {
		successes++
		if !bytes.Equal(salt, stored) {
			t.Fatal("successful runs used different keys")
		}
	}
	if successes == 0 {
		t.Fatal("no creator succeeded")
	}
}

func TestStageOutputPreservesExistingOutputOnFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.gz")
	const original = "previous output"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := []alert.AuditEvent{{Timestamp: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}}
	if _, err := stageOutput(osFileOps(), path, func(w io.Writer) error { return encodeRows(w, rows) }); err == nil {
		t.Fatal("expected invalid timestamp to fail encoding")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != original {
		t.Fatalf("failed write destroyed previous output: %q, %v", got, err)
	}
	assertNoStaging(t, filepath.Dir(path))
}

func TestPublishReplacesOutputWithPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.gz")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	staged, err := stageOutput(osFileOps(), path, func(w io.Writer) error { return encodeRows(w, sampleEvents()) })
	if err != nil {
		t.Fatal(err)
	}
	if err = publishOutputs(osFileOps(), []stagedOutput{staged}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("output is not private: %v", err)
	}
	var rows int
	if _, err = readStream(path, kindFindings, 1, func(int, []byte) (time.Time, error) { rows++; return joinTS, nil }); err != nil || rows != len(sampleEvents()) {
		t.Fatalf("output incomplete: count=%d err=%v", rows, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v %v", entries, err)
	}
}

type failingStreamWriter struct{ err error }

func (w failingStreamWriter) Write([]byte) (int, error) { return 0, w.err }

func TestEncodeRowsReturnsFinalizationErrors(t *testing.T) {
	want := errors.New("write failed")
	// No rows: the failure occurs only when closing the gzip stream.
	if err := encodeRows(failingStreamWriter{want}, []alert.AuditEvent(nil)); !errors.Is(err, want) {
		t.Fatalf("gzip finalization error lost: %v", err)
	}
	if err := encodeRows(io.Discard, sampleEvents()); err != nil {
		t.Fatal(err)
	}
}

func TestReadStreamRejectsTruncatedGzip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.gz")
	staged, err := stageOutput(osFileOps(), path, func(w io.Writer) error { return encodeRows(w, sampleEvents()) })
	if err != nil {
		t.Fatal(err)
	}
	if err = publishOutputs(osFileOps(), []stagedOutput{staged}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, info.Size()-4); err != nil {
		t.Fatal(err)
	}
	if _, err := readStream(path, kindFindings, 1, func(int, []byte) (time.Time, error) { return joinTS, nil }); err == nil {
		t.Fatal("truncated gzip accepted")
	}
}

func TestRunRejectsOutputOverSaltOrInput(t *testing.T) {
	for _, target := range []string{"salt", "input"} {
		t.Run(target, func(t *testing.T) {
			dir := t.TempDir()
			saltPath, input := filepath.Join(dir, "salt"), filepath.Join(dir, "input")
			raw, err := json.Marshal(alert.AuditEvent{V: 1, Check: "webshell"})
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(input, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err = loadOrCreateSalt(saltPath); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(filepath.Join(dir, target))
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err = run([]string{"anonymize", "--salt-file", saltPath, "--out", filepath.Join(dir, target), input}, &out); err == nil {
				t.Fatal("accepted output over protected input")
			}
			after, err := os.Stat(filepath.Join(dir, target))
			if err != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
				t.Fatal("protected file was modified")
			}
		})
	}
}

// The transform below leaks the account it was given. Only the verifier
// stands between that and the output, and it must leave any previous output
// as it was and print no summary.
func TestRunRefusalLeavesOutputUntouched(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprint(existing), func(t *testing.T) {
			dir := t.TempDir()
			input, output := filepath.Join(dir, "input.jsonl"), filepath.Join(dir, "alice.example.com.gz")
			raw, err := json.Marshal(sampleEvents()[0])
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(input, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if existing {
				if err = os.WriteFile(output, []byte("previous output"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			r := newRun()
			r.event = func(a *Anonymizer, e alert.AuditEvent) alert.AuditEvent {
				out := a.Event(e)
				out.Details = e.TenantID
				return out
			}
			var summary bytes.Buffer
			err = r.execute([]string{"anonymize", "--salt-file", filepath.Join(dir, "salt"), "--out", output, input}, &summary)
			if !errors.Is(err, errLeak) || summary.Len() != 0 {
				t.Fatalf("expected refusal without summary, got %v", err)
			}
			body, readErr := os.ReadFile(output)
			if existing {
				if readErr != nil || string(body) != "previous output" {
					t.Fatal("refusal changed existing output")
				}
			} else if !errors.Is(readErr, os.ErrNotExist) {
				t.Fatal("refusal created an output file")
			}
		})
	}
}
