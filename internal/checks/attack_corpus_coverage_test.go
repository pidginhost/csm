//go:build linux && yara

package checks

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackcorpus"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// A known file gap is still an incomplete replay even when the check returned
// normally and did not raise a scan-error finding.
func TestAttackCorpusTierRejectsFileGaps(t *testing.T) {
	c, err := newCorpusSample(t)
	if err != nil {
		t.Fatal(err)
	}
	checks := []namedCheck{{"file_index", func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
		recordCoverageGapPaths(ctx, "file_index", []string{filepath.Join(c.root, corpusAccount, "public_html", "index.php")})
		return nil
	}}}
	if _, err := c.tier(checks); err == nil || !strings.Contains(err.Error(), "file_index") {
		t.Fatalf("file gap error = %v; want file_index coverage failure", err)
	}
}

type corpusUnreadableFile struct {
	realOS
	path string
}

func (o corpusUnreadableFile) Open(path string) (*os.File, error) {
	if path == o.path {
		return nil, os.ErrPermission
	}
	return o.realOS.Open(path)
}

// File scanners report open failures through the completion collector.
// Finding-only validation must not turn such a control into a clean replay.
func TestAttackCorpusFullScanRejectsReadFailures(t *testing.T) {
	useShippedScanEngines(t)
	attackcorpus.Offline(t)
	dir := t.TempDir()
	writeCorpusManifest(t, dir, "unreadable_control", `{
		"name": "unreadable_control", "category": "webshell", "kind": "control", "source": "fixture",
		"description": "an unreadable control", "provenance": "driver regression",
		"files": [
			{"path": "public_html/.htaccess", "b64": "htaccess.b64"},
			{"path": "public_html/wp-config.php", "b64": "wp-config.b64"}
		],
		"expect": {"realtime": {}, "tier": {}, "fullscan": {}}}`)
	for name, content := range map[string]string{"htaccess.b64": "# harmless control\n", "wp-config.b64": corpusWPConfig} {
		encoded := base64.StdEncoding.EncodeToString([]byte(content))
		if err := os.WriteFile(filepath.Join(dir, "webshell", "unreadable_control", name), []byte(encoded), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	samples, err := attackcorpus.Load(dir, "private")
	if err != nil || len(samples) != 1 {
		t.Fatalf("Load = %d samples, %v; want 1", len(samples), err)
	}
	c, err := newCorpusSample(t)
	if err != nil {
		t.Fatal(err)
	}
	previous := osFS
	osFS = corpusUnreadableFile{path: filepath.Join(c.root, corpusAccount, "public_html", ".htaccess")}
	t.Cleanup(func() { osFS = previous })
	o := c.replayFullScan(t, samples[0])
	if o.Err == nil {
		t.Error("full scan accepted a file read failure")
	} else if !strings.Contains(o.Err.Error(), "htaccess") {
		t.Error("driver error does not identify the incomplete htaccess check")
	}
	if attempts := c.networkAttempts(); attempts == 0 || o.NetworkAttempts != attempts {
		t.Errorf("outcome counted %d offline attempts, want %d nonzero attempts even on failure", o.NetworkAttempts, attempts)
	}
	if r := attackcorpus.Judge(samples[0], attackcorpus.FullScan, o); r.Pass {
		t.Error("unreadable control passed the corpus gate")
	}
}

// A failed response is not an untouched-file verdict: the scan job records
// it as failed even when the manifest expects the original bytes to remain.
func TestAttackCorpusFullScanRejectsQuarantineFailures(t *testing.T) {
	useShippedScanEngines(t)
	attackcorpus.Offline(t)
	dir := t.TempDir()
	writeCorpusManifest(t, dir, "quarantine_failure", `{
		"name": "quarantine_failure", "category": "webshell", "kind": "malicious", "source": "fixture",
		"description": "a named shell with an unavailable quarantine", "provenance": "driver regression",
		"files": [{"path": "public_html/wso.php", "selftest": "benign_wordpress_plugin"}],
		"expect": {
			"realtime": {"gap": "not driven by this test"}, "tier": {"gap": "not driven by this test"},
			"fullscan": {"findings": [{"check": "webshell", "file": "public_html/wso.php", "min_severity": "critical"}]}
		}}`)
	samples, err := attackcorpus.Load(dir, "private")
	if err != nil || len(samples) != 1 {
		t.Fatalf("Load = %d samples, %v; want 1", len(samples), err)
	}
	c, err := newCorpusSample(t)
	if err != nil {
		t.Fatal(err)
	}
	previousRoots := fixQuarantineAllowedRoots
	fixQuarantineAllowedRoots = []string{t.TempDir()}
	t.Cleanup(func() { fixQuarantineAllowedRoots = previousRoots })
	o := c.replayFullScan(t, samples[0])
	if o.Err == nil {
		t.Error("full scan accepted a failed quarantine")
	} else if !strings.Contains(o.Err.Error(), "quarantine failed") {
		t.Error("driver error does not identify the failed quarantine")
	}
	if r := attackcorpus.Judge(samples[0], attackcorpus.FullScan, o); r.Pass {
		t.Error("failed quarantine passed the corpus gate")
	}
}

// An offline database still needs a site identity: without it the hidden-link
// scanner cannot distinguish local links from foreign ones and skips its work.
func TestAttackCorpusOfflineDatabaseCompletes(t *testing.T) {
	c, err := newCorpusSample(t)
	if err != nil {
		t.Fatal(err)
	}
	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	findings := checkWPHiddenLinks(corpusAccount, wpDBCreds{queryCtx: ctx}, "wp_")
	if len(findings) != 0 || incomplete.contains("db_content") {
		t.Fatal("offline database did not complete a clean hidden-link scan")
	}
	if got := c.queries.Load(); got != 2 {
		t.Errorf("offline scan ran %d queries, want options and posts", got)
	}
}
