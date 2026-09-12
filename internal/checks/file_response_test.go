package checks

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func fileResponseFixture(t *testing.T, settings string) (*config.Config, string) {
	t.Helper()
	root := t.TempDir()
	cfg, err := config.LoadBytes([]byte("state_path: " + root + "/state\nauto_response:\n  enabled: true\n  quarantine_files: true\n  clean_htaccess: true\n" + settings))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.StatePath, 0700); err != nil {
		t.Fatal(err)
	}
	withQuarantineDirIQ(t, filepath.Join(root, "quarantine"))
	homes := filepath.Join(root, "homes")
	withAccountHomeRoots(t, homes)
	oldExtra := quarantineExtraRoots
	quarantineExtraRoots = nil
	t.Cleanup(func() { quarantineExtraRoots = oldExtra })
	return cfg, homes
}

func responseFile(t *testing.T, homes, account, name string, body []byte) alert.Finding {
	t.Helper()
	path := filepath.Join(homes, account, "public_html", name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	return alert.Finding{Check: "backdoor_binary", Severity: alert.Critical, FilePath: path, Message: "detected test content"}
}

func assertResponseFile(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(want) {
		t.Fatalf("file %s = %q, %v; want original content", path, got, err)
	}
}

func responsePauses(findings []alert.Finding) int {
	n := 0
	for _, f := range findings {
		if f.Check == "auto_response_paused" {
			n++
		}
	}
	return n
}

func TestAutoFileResponsePauseDoesNotBecomeStaleActiveFinding(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st.SetLatestFindings([]alert.Finding{{Check: "auto_response_paused", Message: "old pause"}})
	StoreLatestScanFindings(st, []string{"webshell"}, []alert.Finding{
		{Check: "webshell", Severity: alert.Critical, FilePath: "/home/alice/public_html/test.php"},
		{Check: "auto_response_paused", Message: "new pause"},
	})
	if responsePauses(st.LatestFindings()) != 0 {
		t.Fatal("transient pause remained in the active finding set")
	}
	if !containsFindingCheck(st.LatestFindings(), "webshell") {
		t.Fatal("underlying detection was lost")
	}
}

func TestAutoFileResponsePauseDoesNotCountAsAction(t *testing.T) {
	for _, check := range []string{"backdoor_binary", "htaccess_cgi_handler_abuse"} {
		t.Run(check, func(t *testing.T) {
			cfg, homes := fileResponseFixture(t, "  max_file_actions_per_hour: 1\n")
			body := []byte("deny from all\n")
			seed := responseFile(t, homes, "alice", "seed.bin", body)
			if got := AutoQuarantineFiles(cfg, []alert.Finding{seed}); len(got) != 1 {
				t.Fatalf("seed action = %+v", got)
			}
			f := responseFile(t, homes, "alice", ".htaccess", body)
			f.Check = check
			before := scrapeCounterByAction(t)
			findings, _ := runParallel(cfg, nil, []namedCheck{{"file_response_test", func(context.Context, *config.Config, *state.Store) []alert.Finding {
				return []alert.Finding{f}
			}}}, "deep", false)
			if responsePauses(findings) != 1 {
				t.Fatalf("pause missing: %+v", findings)
			}
			assertResponseFile(t, f.FilePath, body)
			after := scrapeCounterByAction(t)
			for _, action := range []string{"quarantine", "htaccess_clean"} {
				if after[action] != before[action] {
					t.Errorf("pause counted as %s action", action)
				}
			}
		})
	}
}

// Separate realtime and batch counters would let an enabled detector exceed
// the host budget. A new Config value must not reset durable accounting.
func TestAutoFileResponsesShareHostBudget(t *testing.T) {
	cfg, homes := fileResponseFixture(t, "  max_file_actions_per_hour: 2\n  max_file_actions_per_account_per_hour: 20\n")
	payload := makeHighEntropyContent(t, 2048)
	first := responseFile(t, homes, "alice", "first.bin", payload)
	first.Details = "Category: dropper\n"
	qpath, ok := InlineQuarantineGated(cfg, first, first.FilePath, payload)
	if !ok {
		t.Fatal("first realtime quarantine was refused")
	}
	assertResponseFile(t, qpath, payload)
	if _, err := os.Stat(qpath + ".meta"); err != nil {
		t.Fatal(err)
	}
	second := responseFile(t, homes, "bob", "second.bin", payload)
	AutoQuarantineFiles(cfg, []alert.Finding{second})
	if _, err := os.Stat(second.FilePath); !os.IsNotExist(err) {
		t.Fatalf("second file was not quarantined: %v", err)
	}
	reloaded := *cfg
	var blocked []alert.Finding
	for i := 0; i < 12; i++ {
		blocked = append(blocked, responseFile(t, homes, "carol", fmt.Sprintf("blocked-%d.bin", i), payload))
	}
	actions := AutoQuarantineFiles(&reloaded, blocked)
	for _, f := range blocked {
		assertResponseFile(t, f.FilePath, payload)
	}
	if n := responsePauses(actions); n != 1 {
		t.Fatalf("pause findings = %d, want one for the batch", n)
	}
}

func TestAutoFileResponseAccountLimitDoesNotStopOtherAccounts(t *testing.T) {
	cfg, homes := fileResponseFixture(t, "  max_file_actions_per_hour: 10\n  max_file_actions_per_account_per_hour: 1\n")
	body := []byte("test evidence")
	a := responseFile(t, homes, "alice", "first.bin", body)
	b := responseFile(t, homes, "alice", "second.bin", body)
	// Finding attribution is reporting data, not authority to pick a new budget.
	b.TenantID = "different-account"
	c := responseFile(t, homes, "bob", "third.bin", body)
	actions := AutoQuarantineFiles(cfg, []alert.Finding{a, b, c})
	assertResponseFile(t, b.FilePath, body)
	for _, f := range []alert.Finding{a, c} {
		if _, err := os.Stat(f.FilePath); !os.IsNotExist(err) {
			t.Errorf("eligible file remains: %s, %v", f.FilePath, err)
		}
	}
	if n := responsePauses(actions); n != 1 {
		t.Errorf("pause findings = %d, want 1", n)
	}
}

func TestAutoFileResponseFailuresPauseFurtherMutations(t *testing.T) {
	cfg, homes := fileResponseFixture(t, "  max_file_actions_per_hour: 10\n  max_file_actions_per_account_per_hour: 10\n  max_file_action_failures_per_hour: 2\n")
	// A real backup-storage failure that also works when tests run as root.
	if err := os.WriteFile(quarantineDir, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	body := []byte("test evidence")
	var failureActions []alert.Finding
	for i := 0; i < 2; i++ {
		f := responseFile(t, homes, "alice", fmt.Sprintf("failed-%d.bin", i), body)
		failureActions = append(failureActions, AutoQuarantineFiles(cfg, []alert.Finding{f})...)
		assertResponseFile(t, f.FilePath, body)
	}
	if err := os.Remove(quarantineDir); err != nil {
		t.Fatal(err)
	}
	f := responseFile(t, homes, "bob", "after-failure.bin", body)
	actions := AutoQuarantineFiles(cfg, []alert.Finding{f})
	assertResponseFile(t, f.FilePath, body)
	if len(actions) != 0 {
		t.Fatalf("repeated failure pause flooded findings: %+v", actions)
	}
	if len(failureActions) != 1 || failureActions[0].Check != "auto_response_paused" || !strings.Contains(failureActions[0].Details, "failure") {
		t.Fatalf("failure pause not reported when breaker opened: %+v", failureActions)
	}
}

func TestAutoFileResponseCleaningSharesQuarantineBudget(t *testing.T) {
	cfg, homes := fileResponseFixture(t, "  max_file_actions_per_hour: 2\n  max_file_actions_per_account_per_hour: 10\n")
	body := []byte("<?php\n@include('/tmp/payload.php');\necho 'site';\n")
	cleaned := responseFile(t, homes, "alice", "wp-content/plugins/example/main.php", body)
	actions := AutoQuarantineFiles(cfg, []alert.Finding{cleaned})
	assertResponseFile(t, cleaned.FilePath, []byte("<?php\necho 'site';\n"))
	if len(actions) != 1 || !strings.Contains(actions[0].Message, "AUTO-CLEAN:") {
		t.Fatalf("missing clean result: %+v", actions)
	}
	oldRoots, oldBackup := fixHtaccessAllowedRoots, htaccessBackupDirRoot
	fixHtaccessAllowedRoots = []string{homes}
	htaccessBackupDirRoot = filepath.Join(quarantineDir, "pre_clean")
	t.Cleanup(func() { fixHtaccessAllowedRoots, htaccessBackupDirRoot = oldRoots, oldBackup })
	access := responseFile(t, homes, "bob", ".htaccess", []byte("ErrorDocument 404 https://malware.example/missing\n"))
	access.Check = "htaccess_errordocument_hijack"
	AutoCleanHtaccess(cfg, []alert.Finding{access})
	assertResponseFile(t, access.FilePath, []byte(""))
	blocked := responseFile(t, homes, "carol", "blocked.bin", []byte("test evidence"))
	AutoQuarantineFiles(cfg, []alert.Finding{blocked})
	assertResponseFile(t, blocked.FilePath, []byte("test evidence"))
	// Each applied action still has a recoverable pre-clean copy and metadata.
	backups, err := os.ReadDir(filepath.Join(quarantineDir, "pre_clean"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, entry := range backups {
		if strings.HasSuffix(entry.Name(), ".meta") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("recovery sidecars=%d, want 2", n)
	}
}

func TestAutoFileResponseDirectoryRequiresManualReview(t *testing.T) {
	cfg, homes := fileResponseFixture(t, "")
	f := responseFile(t, homes, "alice", "kit/keep.bin", []byte("test evidence"))
	original := f.FilePath
	f.Check = "phishing_directory"
	f.FilePath = filepath.Dir(f.FilePath)
	actions := AutoQuarantineFiles(cfg, []alert.Finding{f})
	assertResponseFile(t, original, []byte("test evidence"))
	if len(actions) != 1 || !strings.Contains(actions[0].Details, "directory") {
		t.Fatalf("unbounded directory refusal not reported: %+v", actions)
	}
}

func TestAutoFileResponseUnavailableStateRefusesMutation(t *testing.T) {
	cfg, homes := fileResponseFixture(t, "")
	if err := os.Remove(cfg.StatePath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.StatePath, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	f := responseFile(t, homes, "alice", "keep.bin", []byte("test evidence"))
	actions := AutoQuarantineFiles(cfg, []alert.Finding{f})
	assertResponseFile(t, f.FilePath, []byte("test evidence"))
	if responsePauses(actions) != 1 {
		t.Fatalf("unavailable state not reported: %+v", actions)
	}
}

func TestAutoFileResponseRollingWindowAndClockRollback(t *testing.T) {
	cfg, homes := fileResponseFixture(t, "  max_file_actions_per_hour: 1\n")
	now := time.Now()
	originalNow := fileResponseNow
	fileResponseNow = func() time.Time { return now }
	t.Cleanup(func() { fileResponseNow = originalNow })
	body := []byte("test evidence")
	first := responseFile(t, homes, "alice", "first.bin", body)
	AutoQuarantineFiles(cfg, []alert.Finding{first})
	now = now.Add(59 * time.Minute)
	blocked := responseFile(t, homes, "bob", "blocked.bin", body)
	AutoQuarantineFiles(cfg, []alert.Finding{blocked})
	assertResponseFile(t, blocked.FilePath, body)
	now = now.Add(time.Minute)
	AutoQuarantineFiles(cfg, []alert.Finding{blocked})
	if _, err := os.Stat(blocked.FilePath); !os.IsNotExist(err) {
		t.Fatalf("expired reservation did not release capacity: %v", err)
	}
	now = now.Add(-2 * time.Hour)
	rollback := responseFile(t, homes, "carol", "rollback.bin", body)
	AutoQuarantineFiles(cfg, []alert.Finding{rollback})
	assertResponseFile(t, rollback.FilePath, body)
}

func TestAutoFileResponseConcurrentAttemptsStayWithinBudget(t *testing.T) {
	cfg, homes := fileResponseFixture(t, "  max_file_actions_per_hour: 3\n")
	body := []byte("test evidence")
	var files []alert.Finding
	for i := 0; i < 20; i++ {
		files = append(files, responseFile(t, homes, "alice", fmt.Sprintf("concurrent-%d.bin", i), body))
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, f := range files {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; AutoQuarantineFiles(cfg, []alert.Finding{f}) }()
	}
	close(start)
	wg.Wait()
	moved := 0
	for _, f := range files {
		if _, err := os.Stat(f.FilePath); os.IsNotExist(err) {
			moved++
		} else {
			assertResponseFile(t, f.FilePath, body)
		}
	}
	if moved < 1 || moved > 3 {
		t.Fatalf("concurrent actions moved %d files; budget permits at most 3", moved)
	}
	// Retry the refused attempts sequentially. Contention must not lose the
	// available slots or allow more than the remaining capacity.
	AutoQuarantineFiles(cfg, files)
	moved = 0
	for _, f := range files {
		if _, err := os.Stat(f.FilePath); os.IsNotExist(err) {
			moved++
		}
	}
	if moved != 3 {
		t.Fatalf("moved %d files after retry; want exactly 3", moved)
	}
}

func TestAutoFileResponseCorruptStateRefusesMutation(t *testing.T) {
	for _, body := range []string{"{", `{"version":2}`, `{"version":1,"attempts":[{}]}`} {
		t.Run(body, func(t *testing.T) {
			cfg, homes := fileResponseFixture(t, "")
			if err := os.WriteFile(filepath.Join(cfg.StatePath, fileResponseStateName), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			f := responseFile(t, homes, "alice", "keep.bin", []byte("test evidence"))
			if responsePauses(AutoQuarantineFiles(cfg, []alert.Finding{f})) != 1 {
				t.Fatal("corrupt state refusal was not reported")
			}
			assertResponseFile(t, f.FilePath, []byte("test evidence"))
		})
	}
}

func TestAutoFileResponseReservationFailureRefusesMutation(t *testing.T) {
	cfg, homes := fileResponseFixture(t, "")
	oldWrite := writeFileResponseState
	writeFileResponseState = func(string, os.FileMode, any) error { return os.ErrPermission }
	t.Cleanup(func() { writeFileResponseState = oldWrite })
	f := responseFile(t, homes, "alice", "keep.bin", []byte("test evidence"))
	if responsePauses(AutoQuarantineFiles(cfg, []alert.Finding{f})) != 1 {
		t.Fatal("reservation failure was not reported")
	}
	assertResponseFile(t, f.FilePath, []byte("test evidence"))
}

func TestAutoFileResponseOutcomeFailureKeepsReservation(t *testing.T) {
	cfg, homes := fileResponseFixture(t, "  max_file_actions_per_hour: 10\n  max_file_action_failures_per_hour: 1\n")
	oldWrite := writeFileResponseState
	calls := 0
	writeFileResponseState = func(path string, mode os.FileMode, value any) error {
		calls++
		if calls == 2 {
			return os.ErrPermission
		}
		return oldWrite(path, mode, value)
	}
	t.Cleanup(func() { writeFileResponseState = oldWrite })
	f := responseFile(t, homes, "alice", "first.bin", []byte("test evidence"))
	actions := AutoQuarantineFiles(cfg, []alert.Finding{f})
	if _, err := os.Stat(f.FilePath); !os.IsNotExist(err) {
		t.Fatalf("first action failed: %v", err)
	}
	if responsePauses(actions) != 1 {
		t.Fatalf("outcome persistence failure not reported: %+v", actions)
	}
	writeFileResponseState = oldWrite
	second := responseFile(t, homes, "bob", "keep.bin", []byte("test evidence"))
	AutoQuarantineFiles(cfg, []alert.Finding{second})
	assertResponseFile(t, second.FilePath, []byte("test evidence"))
}

func TestAutoFileResponseRevalidatesAfterReservation(t *testing.T) {
	for _, name := range []string{"target.bin", "wp-content/plugins/example/main.php", ".htaccess"} {
		t.Run(name, func(t *testing.T) {
			cfg, homes := fileResponseFixture(t, "")
			body := []byte("<?php\n@include('/tmp/payload.php');\necho 'site';\n")
			f := responseFile(t, homes, "alice", name, body)
			oldWrite := writeFileResponseState
			writeFileResponseState = func(path string, mode os.FileMode, value any) error {
				// Replace with a different inode after the original snapshot but before
				// the response has acquired its target descriptor.
				replacement := f.FilePath + ".replacement"
				if err := os.WriteFile(replacement, []byte("replacement content"), 0600); err != nil {
					return err
				}
				if err := os.Rename(replacement, f.FilePath); err != nil {
					return err
				}
				return oldWrite(path, mode, value)
			}
			t.Cleanup(func() { writeFileResponseState = oldWrite })
			if name == ".htaccess" {
				f.Check = "htaccess_errordocument_hijack"
				AutoCleanHtaccess(cfg, []alert.Finding{f})
			} else {
				AutoQuarantineFiles(cfg, []alert.Finding{f})
			}
			assertResponseFile(t, f.FilePath, []byte("replacement content"))
			if _, err := os.Stat(quarantineDir); !os.IsNotExist(err) {
				t.Fatalf("replacement caused recovery write: %v", err)
			}
		})
	}
}

func TestAutoFileResponseFailedCleaningKeepsOriginal(t *testing.T) {
	cfg, homes := fileResponseFixture(t, "")
	body := []byte("<?php echo 'original application';\n")
	f := responseFile(t, homes, "alice", "wp-content/plugins/example/main.php", body)
	actions := AutoQuarantineFiles(cfg, []alert.Finding{f})
	assertResponseFile(t, f.FilePath, body)
	for _, action := range actions {
		if strings.HasPrefix(action.Message, "AUTO-QUARANTINE") {
			t.Fatalf("failed cleaner escalated to file removal: %+v", actions)
		}
	}
}

func TestAutoFileResponseBudgetSurvivesProcessRestart(t *testing.T) {
	// Run a second test process so an in-memory-only limiter cannot satisfy
	// the restart contract. No production binary or server is involved.
	if statePath := os.Getenv("CSM_FILE_RESPONSE_TEST_STATE"); statePath != "" {
		cfg := &config.Config{StatePath: statePath}
		cfg.AutoResponse.Enabled, cfg.AutoResponse.QuarantineFiles = true, true
		cfg.AutoResponse.MaxFileActionsPerHour = 1
		path := os.Getenv("CSM_FILE_RESPONSE_TEST_FILE")
		actions := AutoQuarantineFiles(cfg, []alert.Finding{{Check: "backdoor_binary", Severity: alert.Critical, FilePath: path}})
		assertResponseFile(t, path, []byte("test evidence"))
		if responsePauses(actions) != 1 {
			t.Fatal("restart did not report exhausted budget")
		}
		return
	}
	cfg, homes := fileResponseFixture(t, "  max_file_actions_per_hour: 1\n")
	first := responseFile(t, homes, "alice", "first.bin", []byte("test evidence"))
	AutoQuarantineFiles(cfg, []alert.Finding{first})
	if _, err := os.Stat(first.FilePath); !os.IsNotExist(err) {
		t.Fatalf("first quarantine failed: %v", err)
	}
	next := responseFile(t, homes, "bob", "next.bin", []byte("test evidence"))
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-test.run=^TestAutoFileResponseBudgetSurvivesProcessRestart$", "-test.timeout=30s")
	cmd.Env = append(os.Environ(), "CSM_FILE_RESPONSE_TEST_STATE="+cfg.StatePath, "CSM_FILE_RESPONSE_TEST_FILE="+next.FilePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("restarted response process failed: %v\n%s", err, output)
	}
	assertResponseFile(t, next.FilePath, []byte("test evidence"))
}

func TestAutoFileResponsePoliciesLeaveFilesAndBudgetUntouched(t *testing.T) {
	for _, mode := range []string{"disabled", "quarantine off", "observe"} {
		t.Run(mode, func(t *testing.T) {
			cfg, homes := fileResponseFixture(t, "")
			switch mode {
			case "disabled":
				cfg.AutoResponse.Enabled = false
			case "quarantine off":
				cfg.AutoResponse.QuarantineFiles = false
			case "observe":
				cfg.Mode = config.ModeObserve
			}
			payload := makeHighEntropyContent(t, 2048)
			f := responseFile(t, homes, "alice", "keep.bin", payload)
			f.Details = "Category: dropper\n"
			AutoQuarantineFiles(cfg, []alert.Finding{f})
			if _, ok, _ := InlineQuarantineGatedIdentified(cfg, f, f.FilePath, payload, nil); ok {
				t.Fatal("disabled policy quarantined inline")
			}
			assertResponseFile(t, f.FilePath, payload)
			entries, err := os.ReadDir(cfg.StatePath)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("disabled policy consumed safety state: %v", entries)
			}
		})
	}
}

func TestAutoFileResponseAccountPausesDoNotFloodHost(t *testing.T) {
	cfg, homes := fileResponseFixture(t, "  max_file_actions_per_hour: 100\n  max_file_actions_per_account_per_hour: 1\n")
	notices := 0
	for i := 0; i < 40; i++ {
		account := fmt.Sprintf("account%d", i)
		first := responseFile(t, homes, account, "first.bin", []byte("test evidence"))
		second := responseFile(t, homes, account, "second.bin", []byte("test evidence"))
		notices += responsePauses(AutoQuarantineFiles(cfg, []alert.Finding{first, second}))
		assertResponseFile(t, second.FilePath, []byte("test evidence"))
	}
	if notices != 1 {
		t.Fatalf("one detector produced %d account pause warnings, want one host notice", notices)
	}
}
