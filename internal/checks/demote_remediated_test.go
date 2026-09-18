package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// A file that was flagged and then cleaned changes its bytes, so it satisfies
// neither auto-clear condition and stays Critical for good. On cluster6 that
// left a wp-config cleaned on 2026-09-01 and two index.php stubs cleaned on
// 2026-07-23 sitting at Critical weeks later, beside live findings.
//
// The finding is not cleared -- an attacker must not be able to retire one by
// editing the file -- but it stops competing with live work. Demotion is
// withheld from content that still looks obfuscated or high-entropy, so
// editing a webshell into something the current rules miss cannot buy it.

func TestReverifyDemotesACleanedFile(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)

	// What a real cleanup leaves behind: WordPress's own stub.
	cleaned := filepath.Join(tmp, "index.php")
	if err := os.WriteFile(cleaned, []byte("<?php\n// Silence is golden.\n"), 0644); err != nil {
		t.Fatal(err)
	}

	res := reverifyContentFinding(VerifyInput{
		Check: "suspicious_php_content", Path: cleaned, ContentSHA256: "detection-time-hash",
	})
	if res.Resolved {
		t.Fatalf("a modified file must never auto-clear: %+v", res)
	}
	if !res.Demote {
		t.Fatalf("a cleaned file should stop competing with live findings: %+v", res)
	}
	if !strings.Contains(res.Detail, "confirm remediation") {
		t.Fatalf("detail should ask for confirmation, got %q", res.Detail)
	}
}

func TestReverifyWithholdsDemotionFromObfuscatedReplacement(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)

	// Rewritten so the current rules no longer match, but still built like a
	// packed loader: a decoder bound to a variable and then invoked.
	evasive := filepath.Join(tmp, "evasive.php")
	body := "<?php\n$f = 'base' . '64_' . 'decode';\n$g = 'ass' . 'ert';\n$g($f($_COOKIE['q']));\n"
	if err := os.WriteFile(evasive, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}

	res := reverifyContentFinding(VerifyInput{
		Check: "suspicious_php_content", Path: evasive, ContentSHA256: "detection-time-hash",
	})
	if res.Resolved {
		t.Fatalf("must not clear: %+v", res)
	}
	if res.Demote {
		t.Fatalf("obfuscated replacement must not earn a demotion: %+v", res)
	}
}

func TestReverifyWithholdsDemotionFromHighEntropyReplacement(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)

	// A blob the current rules do not match but that no cleanup produces.
	packed := filepath.Join(tmp, "packed.php")
	var b strings.Builder
	b.WriteString("<?php $d='")
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for i := 0; i < 8000; i++ {
		b.WriteByte(alphabet[(i*7+i/64*13)%len(alphabet)])
	}
	b.WriteString("';\n")
	if err := os.WriteFile(packed, []byte(b.String()), 0644); err != nil {
		t.Fatal(err)
	}

	res := reverifyContentFinding(VerifyInput{
		Check: "suspicious_php_content", Path: packed, ContentSHA256: "detection-time-hash",
	})
	if res.Demote {
		t.Fatalf("high-entropy replacement must not earn a demotion: %+v", res)
	}
}

func TestReverifyWithholdsDemotionFromLowEntropyLivePHP(t *testing.T) {
	for name, body := range map[string]string{
		"direct shell using environment input": "<?php system(getenv('HTTP_X_COMMAND'));\n",
		"fragmented callback":                  "<?php call_user_func('sy'.'stem', getenv('HTTP_X_COMMAND'));\n",
		"expression function call":             "<?php ${'sy'.'stem'}(getenv('HTTP_X_COMMAND'));\n",
		"callback API with fragmented target":  "<?php array_map('sy'.'stem', [getenv('HTTP_X_COMMAND')]);\n",
		"indexed callable":                     "<?php $f = ['sy'.'stem']; $f[0](getenv('HTTP_X_COMMAND'));\n",
		"static payload include":               "<?php include 'payload.php';\n",
		"unlisted direct side effect":          "<?php unlink('/tmp/evidence');\n",
		"request data output":                  "<?php echo $_GET['token'];\n",
		"inline phishing page":                 "<form action='/collect'><input name='password'></form>\n",
		"comment stub with active HTML tail":   "<?php // cleaned\n?><script>fetch('/collect')</script>\n",
		"vertical tab before page output":      "<?php\v// <script>alert(1)</script>\n",
		"form feed before page output":         "<?php\f// <script>alert(1)</script>\n",
	} {
		t.Run(name, func(t *testing.T) {
			tmp := t.TempDir()
			withQuarantineAllowedRoots(t, tmp)
			path := filepath.Join(tmp, "replacement.php")
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}

			res := reverifyContentFinding(VerifyInput{
				Check: "suspicious_php_content", Path: path, ContentSHA256: "detection-time-hash",
			})
			if res.Resolved || res.Demote {
				t.Fatalf("live replacement must stay at its prior severity: %+v", res)
			}
			if !strings.Contains(res.Detail, "active PHP or web content") {
				t.Fatalf("detail should identify the active replacement, got %q", res.Detail)
			}
		})
	}
}

func TestReverifyDoesNotDemoteAReplacementOutsidePHPHeuristics(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)
	path := filepath.Join(tmp, "replacement.js")
	// This is not a keylogger flow, but it is still live credential theft. A
	// keylogger finding rewritten into a different malware family is not a
	// confirmed cleanup.
	body := "navigator.sendBeacon('/collect', localStorage.getItem('token'));\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	res := reverifyContentFinding(VerifyInput{
		Check: "js_keylogger_dataflow", Path: path, ContentSHA256: "detection-time-hash",
	})
	if res.Resolved || res.Demote {
		t.Fatalf("a different live malware family must not earn demotion: %+v", res)
	}
}

func TestReverifyDoesNotReadOversizedReplacementForDemotion(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)
	path := filepath.Join(tmp, "grown.php")
	if err := os.WriteFile(path, []byte("<?php\n// cleaned prefix\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, contentFingerprintMaxBytes+1); err != nil {
		t.Fatal(err)
	}

	res := reverifyContentFinding(VerifyInput{
		Check: "suspicious_php_content", Path: path, ContentSHA256: "detection-time-hash",
	})
	if res.Demote {
		t.Fatalf("oversized replacement must stay unresolved: %+v", res)
	}
	if !strings.Contains(res.Detail, "read limit") {
		t.Fatalf("detail should report the bounded-read refusal, got %q", res.Detail)
	}
}

// The existing clear path must be untouched: identical bytes the current
// classifier no longer flags is still a superseded-heuristic false positive.
func TestReverifyStillClearsUnchangedSupersededContent(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)

	benign := filepath.Join(tmp, "benign.php")
	if err := os.WriteFile(benign, []byte("<?php require_once ABSPATH . 'wp-load.php';"), 0644); err != nil {
		t.Fatal(err)
	}
	res := reverifyContentFinding(VerifyInput{
		Check: "suspicious_php_content", Path: benign, ContentSHA256: FileContentSHA256(benign),
	})
	if !res.Checked || !res.Resolved {
		t.Fatalf("unchanged superseded content must still clear: %+v", res)
	}
	if res.Demote {
		t.Fatalf("a cleared finding needs no demotion: %+v", res)
	}
}

// demoteRecordingStore captures what the sweep asked the store to do.
type demoteRecordingStore struct {
	findings  []alert.Finding
	dismissed map[string]bool
	demoted   map[string]alert.Severity
}

func (s *demoteRecordingStore) LatestFindings() []alert.Finding { return s.findings }
func (s *demoteRecordingStore) DismissFindingIfLatest(f alert.Finding) bool {
	s.dismissed[f.Key()] = true
	return true
}
func (s *demoteRecordingStore) DemoteLatestFinding(f alert.Finding, sev alert.Severity) bool {
	for i := range s.findings {
		if s.findings[i].Key() != f.Key() {
			continue
		}
		s.findings[i].DemotedFrom = s.findings[i].Severity
		s.findings[i].Severity = sev
		s.demoted[f.Key()] = sev
		return true
	}
	return false
}
func (s *demoteRecordingStore) RestoreLatestFindingSeverity(expected alert.Finding) bool {
	for i := range s.findings {
		if s.findings[i].Key() != expected.Key() || s.findings[i].DemotedFrom == alert.Warning {
			continue
		}
		s.findings[i].Severity = s.findings[i].DemotedFrom
		s.findings[i].DemotedFrom = alert.Warning
		return true
	}
	return false
}

func TestSweepDemotesACleanedFileInsteadOfDismissingIt(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)

	cleaned := filepath.Join(tmp, "index.php")
	if err := os.WriteFile(cleaned, []byte("<?php\n// Silence is golden.\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f := alert.Finding{
		Check: "suspicious_php_content", Message: "suspicious PHP content in index.php",
		FilePath: cleaned, ContentSHA256: "detection-time-hash", Severity: alert.Critical,
	}
	store := &demoteRecordingStore{
		findings:  []alert.Finding{f},
		dismissed: map[string]bool{},
		demoted:   map[string]alert.Severity{},
	}

	got := ReverifyStaleFindings(store)
	if len(got) != 1 || !got[0].Demoted {
		t.Fatalf("sweep should report one demotion for the audit log, got %+v", got)
	}
	if store.dismissed[f.Key()] {
		t.Fatal("sweep dismissed a finding it should only have demoted")
	}
	if sev, ok := store.demoted[f.Key()]; !ok || sev != alert.Warning {
		t.Fatalf("sweep should have demoted to Warning, got %v (present=%v)", sev, ok)
	}
}

func TestSweepRestoresSeverityWhenDemotedContentBecomesActiveAgain(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)
	path := filepath.Join(tmp, "index.php")
	if err := os.WriteFile(path, []byte("<?php\n// Silence is golden.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := alert.Finding{
		Check: "suspicious_php_content", Message: "suspicious PHP content in index.php",
		Details: "original evidence", FilePath: path, ContentSHA256: "detection-time-hash",
		Severity: alert.Critical,
	}
	store := &demoteRecordingStore{
		findings: []alert.Finding{f}, dismissed: map[string]bool{}, demoted: map[string]alert.Severity{},
	}
	if got := ReverifyStaleFindings(store); len(got) != 1 || !got[0].Demoted {
		t.Fatalf("first sweep should demote the cleaned file, got %+v", got)
	}
	// A static include is valid application syntax and deliberately does not
	// match the owning heuristic. It can still load a replacement payload, so
	// losing the inert-content evidence must restore the saved severity.
	if err := os.WriteFile(path, []byte("<?php include 'payload.php';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := reverifyContentFinding(VerifyInput{
		Check: f.Check, Path: path, ContentSHA256: f.ContentSHA256,
	})
	if !res.Checked || res.Resolved || res.Demote || !strings.Contains(res.Detail, "active PHP") {
		t.Fatalf("static loader should reach the conservative safety gate: %+v", res)
	}

	got := ReverifyStaleFindings(store)
	if len(got) != 1 || !got[0].Promoted {
		t.Fatalf("second sweep should restore a live finding, got %+v", got)
	}
	if store.findings[0].Severity != alert.Critical || store.findings[0].DemotedFrom != alert.Warning {
		t.Fatalf("live finding stayed demoted: %+v", store.findings[0])
	}
	if store.findings[0].Check != f.Check || store.findings[0].Message != f.Message || store.findings[0].Details != f.Details {
		t.Fatalf("severity restoration changed finding identity: %+v", store.findings[0])
	}
}

func TestSweepRestoresSeverityWhenDemotedContentBecomesUnverifiable(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)
	path := filepath.Join(tmp, "index.php")
	if err := os.WriteFile(path, []byte("<?php\n// Silence is golden.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := alert.Finding{
		Check: "suspicious_php_content", Message: "suspicious PHP content in index.php",
		FilePath: path, ContentSHA256: "detection-time-hash", Severity: alert.Critical,
	}
	store := &demoteRecordingStore{
		findings: []alert.Finding{f}, dismissed: map[string]bool{}, demoted: map[string]alert.Severity{},
	}
	if got := ReverifyStaleFindings(store); len(got) != 1 || !got[0].Demoted {
		t.Fatalf("first sweep should demote the inert stub, got %+v", got)
	}
	if err := os.Truncate(path, contentFingerprintMaxBytes+1); err != nil {
		t.Fatal(err)
	}

	got := ReverifyStaleFindings(store)
	if len(got) != 1 || !got[0].Promoted {
		t.Fatalf("an unverifiable replacement should restore severity, got %+v", got)
	}
	if store.findings[0].Severity != alert.Critical || store.findings[0].DemotedFrom != alert.Warning {
		t.Fatalf("unverifiable finding stayed demoted: %+v", store.findings[0])
	}
}

// The findings that motivated demotion were yara_match_scheduled: two
// index.php files cleaned to WordPress's own stub on 2026-07-23, still
// Critical six weeks later. Eligibility is decided by the replacement's
// content, not by which detector fired -- a YARA hit on an inert stub is no
// more dangerous than a heuristic hit on the same bytes, and excluding the
// scanner-backed checks left the feature unable to help the case it was built
// for. Asserted on the predicate because reverifyContentFinding cannot reach
// the gate for those checks without a scanner backend in the test binary.
func TestDemotionEligibilityCoversEveryContentReverifiableCheck(t *testing.T) {
	for _, check := range contentReverifiableChecks {
		if !changedContentDemotionEligible(check) {
			t.Errorf("%s is re-verifiable but cannot demote, so a cleaned file stays Critical forever", check)
		}
	}
}

func TestDemotionEligibilityRejectsUnrelatedChecks(t *testing.T) {
	for _, check := range []string{"web_exposed_backup_archive", "outdated_plugins", "suspicious_crontab"} {
		if changedContentDemotionEligible(check) {
			t.Errorf("%s has no content gate behind it and must not be demotable", check)
		}
	}
}

// Eligibility must not become a way around the content gate: a live payload
// stays Critical on every check that can be exercised here.
func TestReverifyKeepsLivePayloadCriticalWhateverDetectorFlaggedIt(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)

	live := filepath.Join(tmp, "live.php")
	if err := os.WriteFile(live, []byte("<?php\n$f = 'base' . '64_' . 'decode';\n$g = 'ass' . 'ert';\n$g($f($_COOKIE['q']));\n"), 0644); err != nil {
		t.Fatal(err)
	}

	for _, check := range []string{"suspicious_php_content", "obfuscated_php"} {
		res := reverifyContentFinding(VerifyInput{
			Check: check, Path: live, ContentSHA256: "detection-time-hash",
		})
		if res.Demote {
			t.Errorf("%s: live payload must not earn a demotion: %+v", check, res)
		}
	}
}
