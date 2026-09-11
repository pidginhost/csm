package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/platform"
)

func TestDeriveSweepMatchesWindowedAggregate(t *testing.T) {
	at := time.Now()
	rows := []alert.Finding{
		critical("a", "webshell", "1", at.Add(-2*time.Hour)).Finding,
		critical("b", "webshell", "2", at.Add(-2*time.Hour)).Finding,
		critical("c", "webshell", "3", at).Finding,
	}
	fires, accounts := Derive(at, rows, time.Hour)
	if len(fires) != 0 || accounts != 1 {
		t.Fatalf("sweep and aggregate disagree: fires=%v accounts=%d", fires, accounts)
	}
}

func TestReplayPersistedAdvancesOnIgnoredEvents(t *testing.T) {
	at := time.Now()
	events := []Event{
		critical("a", "webshell", "1", at),
		critical("b", "webshell", "2", at),
		critical("c", "webshell", "3", at),
		critical("ignored", "account_scan", "4", at.Add(2*time.Hour)),
		critical("ignored", "account_scan", "5", at.Add(4*time.Hour)),
	}
	fires, spread, latched := replayPersisted(events, time.Hour)
	if fires != 1 || latched != 50 || spread.Points() != 5 || spread.AtLeast(3) != 1 {
		t.Fatalf("ignored arrivals did not advance replay: fires=%d latched=%v spread=%v", fires, latched, spread)
	}
}

func recording(t *testing.T) string {
	t.Helper()
	at := time.Now()
	var data bytes.Buffer
	for i, account := range []string{"a", "b", "c"} {
		e := alert.AuditEvent{Timestamp: at.Add(time.Duration(i) * time.Hour), Severity: "CRITICAL", Check: "webshell", Message: "finding for " + account, FilePath: "/home/" + account + "/site.php"}
		if err := json.NewEncoder(&data).Encode(e); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "stream.jsonl")
	if err := os.WriteFile(path, data.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunUsesRecordingWithoutHostDiscovery(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	var out bytes.Buffer
	if err := run([]string{recording(t)}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "attributed 3 (100.0% of eligible)") {
		t.Fatalf("recorded path identities were not resolved: %s", out.String())
	}
	if !platform.SetOverrides(platform.Overrides{}) {
		t.Fatal("offline replay initialized host discovery")
	}
}

func TestRunWindowSelectsActualCorrelationBound(t *testing.T) {
	path := recording(t)
	for _, window := range []string{"0", "3h"} {
		var out bytes.Buffer
		if err := run([]string{"--window", window, path}, &out); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "1 coordinated_attack firings, max accounts 3") {
			t.Errorf("window %s was still constrained by the production default: %s", window, out.String())
		}
	}
}

func TestRunRejectsNegativeDurations(t *testing.T) {
	path := recording(t)
	for _, flag := range []string{"--window", "--batch-gap"} {
		if err := run([]string{flag, "-1s", path}, &bytes.Buffer{}); err == nil {
			t.Errorf("accepted negative %s", flag)
		}
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestRunReportsOutputFailure(t *testing.T) {
	want := errors.New("output unavailable")
	if err := run([]string{recording(t)}, failingWriter{want}); !errors.Is(err, want) {
		t.Fatalf("output error = %v, want %v", err, want)
	}
}

func TestReadStreamKeepsNonzeroTimestamps(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		var data bytes.Buffer
		writer := &data
		var raw bytes.Buffer
		for _, at := range []time.Time{time.Now(), {}, time.Unix(1, 0)} {
			if err := json.NewEncoder(&raw).Encode(alert.AuditEvent{Timestamp: at, Check: "webshell"}); err != nil {
				t.Fatal(err)
			}
		}
		suffix := ".jsonl"
		if compressed {
			gz := gzip.NewWriter(writer)
			if _, err := gz.Write(raw.Bytes()); err != nil {
				t.Fatal(err)
			}
			if err := gz.Close(); err != nil {
				t.Fatal(err)
			}
			suffix += ".gz"
		} else {
			data = raw
		}
		path := filepath.Join(t.TempDir(), "stream"+suffix)
		if err := os.WriteFile(path, data.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		events, skipped, err := readStream(path)
		if err != nil || len(events) != 2 || skipped != 1 || !events[0].At.Equal(time.Unix(1, 0)) {
			t.Fatalf("compressed=%v: events=%v skipped=%d err=%v", compressed, events, skipped, err)
		}
	}
}

func TestRunReportsInvalidRecordings(t *testing.T) {
	for _, tc := range []struct{ name, data string }{
		{"bad.jsonl", "{invalid json}"},
		{"bad.jsonl.gz", "invalid gzip"},
	} {
		path := filepath.Join(t.TempDir(), tc.name)
		if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := run([]string{path}, &out); err == nil || out.Len() != 0 {
			t.Fatalf("invalid recording: error=%v output=%q", err, out.String())
		}
	}
}
