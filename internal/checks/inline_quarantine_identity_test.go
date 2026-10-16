package checks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func withQuarantineDirIdentity(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := quarantineDir
	quarantineDir = dir
	t.Cleanup(func() { quarantineDir = old })
	return dir
}

// The realtime scanner reads content from the fanotify event descriptor, then
// quarantine re-identified the file by path. An attacker who replaces the file
// in that window gets CSM to move the replacement while the malware it actually
// scanned survives under another name.
func TestInlineQuarantine_RefusesFileReplacedAfterScan(t *testing.T) {
	withQuarantineDirIdentity(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "evil.php")
	payload := []byte(generateHighEntropyPHP(8000))
	writeTestFile(t, target, payload)

	// Identity of the file the scanner actually read.
	scanned, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("stat scanned file: %v", err)
	}

	// The attacker swaps in a different inode after detection.
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, target, []byte("<?php // an ordinary file\n"))

	f := alert.Finding{
		Severity: alert.Critical,
		Check:    "signature_match_realtime",
		Details:  "Category: dropper\nDescription: PHP goto obfuscation\nMatched: goto",
		FilePath: target,
	}
	if qPath, ok := InlineQuarantineIdentified(f, target, payload, scanned); ok {
		t.Fatalf("quarantined the replacement instead of refusing: %s", qPath)
	}
	if _, err := os.Lstat(target); err != nil {
		t.Errorf("the replacement was moved anyway: %v", err)
	}
}

// The ordinary case still quarantines: identity matches what was scanned.
func TestInlineQuarantine_MovesTheScannedFile(t *testing.T) {
	qdir := withQuarantineDirIdentity(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "evil.php")
	payload := []byte(generateHighEntropyPHP(8000))
	writeTestFile(t, target, payload)

	scanned, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("stat scanned file: %v", err)
	}

	f := alert.Finding{
		Severity: alert.Critical,
		Check:    "signature_match_realtime",
		Details:  "Category: dropper\nDescription: PHP goto obfuscation\nMatched: goto",
		FilePath: target,
	}
	qPath, ok := InlineQuarantineIdentified(f, target, payload, scanned)
	if !ok {
		t.Fatal("a file matching what was scanned must still be quarantined")
	}
	if filepath.Dir(qPath) != qdir {
		t.Errorf("quarantined outside the quarantine directory: %s", qPath)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Errorf("original still present after quarantine: %v", err)
	}
}

// The fanotify analyzer holds the event descriptor until the event's scan
// returns, so a signature match is quarantined while CSM has the file open.
func TestInlineQuarantine_MovesTheScannedFileWhileEventDescriptorOpen(t *testing.T) {
	withQuarantineDirIdentity(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "evil.php")
	payload := []byte(generateHighEntropyPHP(8000))
	writeTestFile(t, target, payload)
	event, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer event.Close()
	scanned, err := event.Stat()
	if err != nil {
		t.Fatal(err)
	}

	f := alert.Finding{
		Severity: alert.Critical,
		Check:    "signature_match_realtime",
		Details:  "Category: dropper\nDescription: PHP goto obfuscation\nMatched: goto",
		FilePath: target,
	}
	if qPath, ok := InlineQuarantineIdentified(f, target, payload, scanned); !ok || qPath == "" {
		t.Fatal("signature match was not quarantined while the event descriptor was open")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Errorf("original still present after quarantine: %v", err)
	}
}

func TestInlineQuarantineAcceptsConfirmedCriticalPHPContent(t *testing.T) {
	for _, check := range []string{
		"webshell_content_realtime",
		"obfuscated_php_realtime",
		"webshell_realtime",
		"php_in_uploads_realtime",
	} {
		t.Run(check, func(t *testing.T) {
			qdir := withQuarantineDirIdentity(t)
			target := filepath.Join(t.TempDir(), "payload.php")
			payload := []byte("<?php confirmed malicious content")
			if err := os.WriteFile(target, payload, 0600); err != nil {
				t.Fatal(err)
			}
			scanned, err := os.Stat(target)
			if err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{StatePath: t.TempDir()}
			cfg.AutoResponse.Enabled = true
			cfg.AutoResponse.QuarantineFiles = true
			finding := alert.Finding{
				Check: check, Severity: alert.Critical, FilePath: target,
				Timestamp: time.Unix(1_700_000_000, 0),
			}

			qpath, ok, paused := InlineQuarantineConfirmedPHPGatedIdentified(cfg, &finding, target, payload, scanned)
			if !ok || paused != nil {
				t.Fatalf("qpath=%q ok=%v paused=%+v, want applied", qpath, ok, paused)
			}
			if !finding.AutoFileResponseEvaluated {
				t.Fatal("applied response was not marked evaluated")
			}
			if filepath.Dir(qpath) != qdir {
				t.Fatalf("qpath=%q, want direct child of %q", qpath, qdir)
			}
			if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
				t.Fatalf("source still present: %v", statErr)
			}
			if got, readErr := os.ReadFile(qpath); readErr != nil || string(got) != string(payload) {
				t.Fatalf("quarantine content=%q err=%v", got, readErr)
			}
			metaData, err := os.ReadFile(qpath + ".meta")
			if err != nil {
				t.Fatal(err)
			}
			var meta QuarantineMeta
			if err := json.Unmarshal(metaData, &meta); err != nil {
				t.Fatal(err)
			}
			if meta.Reason != "Inline quarantine: confirmed realtime PHP content" {
				t.Errorf("reason=%q, want confirmed realtime PHP content", meta.Reason)
			}
			if meta.FindingID != alert.FindingID(finding) {
				t.Errorf("finding id=%q, want %q", meta.FindingID, alert.FindingID(finding))
			}
		})
	}
}

func TestConfirmedCriticalPHPContentRequiresPinnedSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name    string
		check   string
		data    []byte
		scanned bool
	}{
		{name: "missing data", check: "webshell_content_realtime", scanned: true},
		{name: "missing identity", check: "webshell_content_realtime", data: []byte("payload")},
		{name: "review-only dropper", check: "php_dropper_realtime", data: []byte("payload"), scanned: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withQuarantineDirIdentity(t)
			target := filepath.Join(t.TempDir(), "payload.php")
			if err := os.WriteFile(target, []byte("payload"), 0600); err != nil {
				t.Fatal(err)
			}
			var scanned os.FileInfo
			if tc.scanned {
				var err error
				scanned, err = os.Stat(target)
				if err != nil {
					t.Fatal(err)
				}
			}
			cfg := &config.Config{StatePath: t.TempDir()}
			cfg.AutoResponse.Enabled = true
			cfg.AutoResponse.QuarantineFiles = true
			finding := alert.Finding{Check: tc.check, Severity: alert.Critical, FilePath: target}

			if qpath, ok, paused := InlineQuarantineConfirmedPHPGatedIdentified(cfg, &finding, target, tc.data, scanned); ok || qpath != "" || paused != nil {
				t.Fatalf("qpath=%q ok=%v paused=%+v, want refusal", qpath, ok, paused)
			}
			if _, err := os.Stat(target); err != nil {
				t.Fatalf("refusal changed source: %v", err)
			}
		})
	}
}
