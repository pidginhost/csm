package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func TestAutoFileResponseDuplicateDetectionsDoNotTripBreaker(t *testing.T) {
	cfg, homes := fileResponseFixture(t, "  max_file_actions_per_hour: 2\n  max_file_action_failures_per_hour: 1\n")
	body := []byte("<?php\n@include('/tmp/payload.php');\necho 'site';\n")
	first := responseFile(t, homes, "alice", "wp-content/plugins/example/main.php", body)
	duplicate := first
	duplicate.Check = "obfuscated_php"
	// Detectors may spell the same path differently. Deduplication must use
	// the target path, not the finding key or the literal path spelling.
	duplicate.FilePath = filepath.Dir(first.FilePath) + "/./main.php"
	other := responseFile(t, homes, "bob", "other.bin", []byte("test evidence"))

	actions := AutoQuarantineFiles(cfg, []alert.Finding{first, duplicate, other})
	assertResponseFile(t, first.FilePath, []byte("<?php\necho 'site';\n"))
	if _, err := os.Stat(other.FilePath); !os.IsNotExist(err) {
		t.Errorf("duplicate detection blocked another account's response: %v", err)
	}
	if len(actions) != 2 || responsePauses(actions) != 0 {
		t.Errorf("expected one clean and one quarantine, got %+v", actions)
	}
	ledger, err := readFileResponseState(filepath.Join(cfg.StatePath, fileResponseStateName), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger.Attempts) != 2 {
		t.Fatalf("attempts = %d, want 2 unique targets", len(ledger.Attempts))
	}
	for _, attempt := range ledger.Attempts {
		if attempt.Failed {
			t.Error("duplicate detection charged a spurious cleaning failure")
		}
	}
}

func TestAutoFileResponseScanDeliveryDoesNotRetryCleaning(t *testing.T) {
	cfg, homes := fileResponseFixture(t, "  max_file_actions_per_hour: 2\n  max_file_action_failures_per_hour: 1\n")
	f := responseFile(t, homes, "alice", "wp-content/plugins/example/main.php", []byte("<?php\n@include('/tmp/payload.php');\necho 'site';\n"))
	findings, _ := runParallel(cfg, nil, []namedCheck{{"file_response_test", func(context.Context, *config.Config, *state.Store) []alert.Finding {
		return []alert.Finding{f}
	}}}, "deep", false)
	if !containsFindingCheck(findings, f.Check) {
		t.Fatal("scan lost the original detection")
	}
	assertResponseFile(t, f.FilePath, []byte("<?php\necho 'site';\n"))
	// The daemon receives these same findings through its alert queue and
	// invokes the responder again. Delivery must not spend another attempt.
	if actions := AutoQuarantineFiles(cfg, findings); len(actions) != 0 {
		t.Errorf("scan delivery retried a completed response: %+v", actions)
	}
	other := responseFile(t, homes, "bob", "other.bin", []byte("test evidence"))
	AutoQuarantineFiles(cfg, []alert.Finding{other})
	if _, err := os.Stat(other.FilePath); !os.IsNotExist(err) {
		t.Errorf("scan delivery spent another account's capacity: %v", err)
	}
}

func TestAutoFileResponseIncompleteStateRefusesMutation(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for name, body := range map[string]string{
		"missing attempts": `{"version":1}`,
		"null attempts":    `{"version":1,"attempts":null}`,
		"missing account":  fmt.Sprintf(`{"version":1,"attempts":[{"at":%q,"failed":false}]}`, now),
		"null account":     fmt.Sprintf(`{"version":1,"attempts":[{"at":%q,"account":null,"failed":false}]}`, now),
		"missing outcome":  fmt.Sprintf(`{"version":1,"attempts":[{"at":%q,"account":"alice"}]}`, now),
		"null outcome":     fmt.Sprintf(`{"version":1,"attempts":[{"at":%q,"account":"alice","failed":null}]}`, now),
	} {
		t.Run(name, func(t *testing.T) {
			cfg, homes := fileResponseFixture(t, "  max_file_actions_per_account_per_hour: 1\n  max_file_action_failures_per_hour: 1\n")
			statePath := filepath.Join(cfg.StatePath, fileResponseStateName)
			if err := os.WriteFile(statePath, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			account := "alice"
			if strings.Contains(name, "outcome") {
				account = "bob" // The failure breaker must protect other accounts too.
			}
			f := responseFile(t, homes, account, "keep.bin", []byte("test evidence"))
			actions := AutoQuarantineFiles(cfg, []alert.Finding{f})
			if len(actions) != 1 || actions[0].Check != "auto_response_paused" || !strings.Contains(actions[0].Details, "cannot be read") {
				t.Errorf("incomplete ledger did not pause for repair: %+v", actions)
			}
			assertResponseFile(t, f.FilePath, []byte("test evidence"))
			assertResponseFile(t, statePath, []byte(body))
		})
	}
}

func TestAutoFileResponseHtaccessDuplicatesAndDeliveryShareAttempt(t *testing.T) {
	cfg, homes := fileResponseFixture(t, "  max_file_actions_per_hour: 2\n")
	oldRoots, oldBackup := fixHtaccessAllowedRoots, htaccessBackupDirRoot
	fixHtaccessAllowedRoots = []string{homes}
	htaccessBackupDirRoot = filepath.Join(quarantineDir, "pre_clean")
	t.Cleanup(func() { fixHtaccessAllowedRoots, htaccessBackupDirRoot = oldRoots, oldBackup })
	f := responseFile(t, homes, "alice", ".htaccess", []byte("ErrorDocument 404 https://malware.example/missing\n"))
	f.Check = "htaccess_errordocument_hijack"
	alias := f
	alias.FilePath = filepath.Dir(f.FilePath) + "/./.htaccess"
	findings := []alert.Finding{f, alias}
	if actions := AutoCleanHtaccess(cfg, findings); len(actions) != 1 || responsePauses(actions) != 0 {
		t.Fatalf("expected one clean, got %+v", actions)
	}
	assertResponseFile(t, f.FilePath, nil)
	if actions := AutoCleanHtaccess(cfg, findings); len(actions) != 0 {
		t.Errorf("delivery retried access-file cleaning: %+v", actions)
	}
	other := responseFile(t, homes, "bob", "other.bin", []byte("test evidence"))
	AutoQuarantineFiles(cfg, []alert.Finding{other})
	if _, err := os.Stat(other.FilePath); !os.IsNotExist(err) {
		t.Errorf("duplicate access-file cleaning spent another account's capacity: %v", err)
	}
}

// A cleaner that recognizes no injection refuses the file; it does not fail.
// Charging those refusals lets a handful of plugin-path false positives trip
// the host-wide breaker and stop quarantine for every other path.
func TestAutoFileResponseCleanerRefusalIsNotAFailure(t *testing.T) {
	cfg, homes := fileResponseFixture(t, "  max_file_action_failures_per_hour: 1\n")
	body := []byte("<?php echo 'original application';\n")
	refused := responseFile(t, homes, "alice", "wp-content/plugins/example/main.php", body)
	actions := AutoQuarantineFiles(cfg, []alert.Finding{refused})
	assertResponseFile(t, refused.FilePath, body)
	if len(actions) != 1 || actions[0].Severity != alert.Warning || !strings.Contains(actions[0].Message, "manual review required") {
		t.Fatalf("refusal not reported for review: %+v", actions)
	}
	other := responseFile(t, homes, "bob", "other.bin", []byte("test evidence"))
	if pauses := responsePauses(AutoQuarantineFiles(cfg, []alert.Finding{other})); pauses != 0 {
		t.Error("cleaner refusal tripped the failure breaker")
	}
	if _, err := os.Stat(other.FilePath); !os.IsNotExist(err) {
		t.Errorf("cleaner refusal stopped quarantine on another path: %v", err)
	}
}

func TestAutoFileResponseChangedTargetDoesNotTripBreaker(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(fmt.Sprintf("removed=%v", remove), func(t *testing.T) {
			cfg, homes := fileResponseFixture(t, "  max_file_action_failures_per_hour: 1\n")
			f := responseFile(t, homes, "alice", "target.bin", []byte("test evidence"))
			oldWrite := writeFileResponseState
			changed := false
			writeFileResponseState = func(path string, mode os.FileMode, value any) error {
				if err := oldWrite(path, mode, value); err != nil {
					return err
				}
				if changed {
					return nil
				}
				changed = true
				if remove {
					return os.Remove(f.FilePath)
				}
				return os.WriteFile(f.FilePath, []byte("updated content"), 0600)
			}
			t.Cleanup(func() { writeFileResponseState = oldWrite })
			AutoQuarantineFiles(cfg, []alert.Finding{f})
			writeFileResponseState = oldWrite
			if !remove {
				assertResponseFile(t, f.FilePath, []byte("updated content"))
			}
			assertOtherAccountCanRespond(t, cfg, homes)
		})
	}
}

func TestAutoFileResponseCleanerSafetyRefusalsDoNotTripBreaker(t *testing.T) {
	for _, kind := range []string{"oversized PHP", "changed PHP", "changed htaccess", "clean htaccess"} {
		t.Run(kind, func(t *testing.T) {
			cfg, homes := fileResponseFixture(t, "  max_file_action_failures_per_hour: 1\n")
			name := "wp-content/plugins/example/main.php"
			body := []byte("<?php\n@include('/tmp/payload.php');\necho 'site';\n")
			if strings.Contains(kind, "htaccess") {
				name = ".htaccess"
				body = []byte("ErrorDocument 404 https://malware.example/missing\n")
				oldRoots, oldBackup := fixHtaccessAllowedRoots, htaccessBackupDirRoot
				fixHtaccessAllowedRoots, htaccessBackupDirRoot = []string{homes}, filepath.Join(quarantineDir, "pre_clean")
				t.Cleanup(func() { fixHtaccessAllowedRoots, htaccessBackupDirRoot = oldRoots, oldBackup })
			}
			if kind == "clean htaccess" {
				body = []byte("# ordinary configuration\n")
			}
			f := responseFile(t, homes, "alice", name, body)
			want := body
			if kind == "oversized PHP" {
				oldMax := cleanMaxFileSize
				cleanMaxFileSize = 1
				t.Cleanup(func() { cleanMaxFileSize = oldMax })
			}
			if strings.HasPrefix(kind, "changed") {
				oldStore := storeQuarantineBackup
				want = []byte("replacement content")
				storeQuarantineBackup = func(path string, data []byte, meta QuarantineMeta, mode os.FileMode) error {
					if err := oldStore(path, data, meta, mode); err != nil {
						return err
					}
					return os.WriteFile(f.FilePath, want, 0600)
				}
				t.Cleanup(func() { storeQuarantineBackup = oldStore })
			}
			if name == ".htaccess" {
				f.Check = "htaccess_errordocument_hijack"
				AutoCleanHtaccess(cfg, []alert.Finding{f})
			} else {
				AutoQuarantineFiles(cfg, []alert.Finding{f})
			}
			assertResponseFile(t, f.FilePath, want)
			assertOtherAccountCanRespond(t, cfg, homes)
		})
	}
}

func TestAutoFileResponseQuarantineIdentityRefusalDoesNotTripBreaker(t *testing.T) {
	cfg, homes := fileResponseFixture(t, "  max_file_action_failures_per_hour: 1\n")
	f := responseFile(t, homes, "alice", "target.bin", []byte("test evidence"))
	oldMove := quarantineTargetFn
	quarantineTargetFn = func(path, qpath string, info os.FileInfo, data []byte) error {
		if err := os.WriteFile(path, []byte("updated content"), 0600); err != nil {
			return err
		}
		return oldMove(path, qpath, info, data)
	}
	t.Cleanup(func() { quarantineTargetFn = oldMove })
	AutoQuarantineFiles(cfg, []alert.Finding{f})
	quarantineTargetFn = oldMove
	assertResponseFile(t, f.FilePath, []byte("updated content"))
	assertOtherAccountCanRespond(t, cfg, homes)
}

func assertOtherAccountCanRespond(t *testing.T, cfg *config.Config, homes string) {
	t.Helper()
	other := responseFile(t, homes, "bob", "other.bin", []byte("test evidence"))
	AutoQuarantineFiles(cfg, []alert.Finding{other})
	if _, err := os.Stat(other.FilePath); !os.IsNotExist(err) {
		t.Errorf("refused target stopped another account's response: %v", err)
	}
	ledger, err := readFileResponseState(filepath.Join(cfg.StatePath, fileResponseStateName), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger.Attempts) != 2 {
		t.Errorf("attempts = %d, want refusal and quarantine charged", len(ledger.Attempts))
	}
	for _, attempt := range ledger.Attempts {
		if attempt.Failed {
			t.Error("refusal charged as action failure")
		}
	}
}

func TestQuarantineFindingFileCleanerRefusalNeedsReview(t *testing.T) {
	for _, oversized := range []bool{false, true} {
		t.Run(fmt.Sprintf("oversized=%v", oversized), func(t *testing.T) {
			_, homes := fileResponseFixture(t, "")
			body := []byte("<?php echo 'original application';\n")
			f := responseFile(t, homes, "alice", "wp-content/plugins/example/main.php", body)
			f.Check = "webshell"
			if oversized {
				oldMax := cleanMaxFileSize
				cleanMaxFileSize = 1
				t.Cleanup(func() { cleanMaxFileSize = oldMax })
			}
			if result, eligible := QuarantineFindingFile(f); eligible || result.Success {
				t.Errorf("refusal should be left for review: eligible=%v result=%+v", eligible, result)
			}
			assertResponseFile(t, f.FilePath, body)
		})
	}
}

func TestFormatCleanResultDistinguishesRefusal(t *testing.T) {
	result := FormatCleanResult(CleanResult{Path: "/home/alice/public_html/example.php", Refused: true, Error: "manual review required"})
	if !strings.HasPrefix(result, "REFUSED") || !strings.Contains(result, "manual review required") {
		t.Fatalf("cleaner refusal reported as failure: %s", result)
	}
}

func TestAutoFileResponseHtaccessOutsideRootsDoesNotTripBreaker(t *testing.T) {
	cfg, homes := fileResponseFixture(t, "  max_file_action_failures_per_hour: 1\n")
	f := responseFile(t, homes, "alice", ".htaccess", []byte("ErrorDocument 404 https://malware.example/missing\n"))
	f.Check = "htaccess_errordocument_hijack"
	oldRoots := fixHtaccessAllowedRoots
	fixHtaccessAllowedRoots = []string{filepath.Join(homes, "carol")}
	t.Cleanup(func() { fixHtaccessAllowedRoots = oldRoots })
	AutoCleanHtaccess(cfg, []alert.Finding{f})
	assertResponseFile(t, f.FilePath, []byte("ErrorDocument 404 https://malware.example/missing\n"))
	assertOtherAccountCanRespond(t, cfg, homes)
}

// Refusal is accounting for the automatic breaker. Manual remediation shares
// these checks, so operators must still see the refusing check's own message
// on one line, without the classification leaking into it.
func TestFileResponseRefusalKeepsOperatorMessage(t *testing.T) {
	_, err := sanitizeFixPath("", nil)
	if !errors.Is(err, errFileResponseRefused) || err.Error() != "file path is required" {
		t.Errorf("path refusal = %q, refused=%v", err, errors.Is(err, errFileResponseRefused))
	}
	missing := fmt.Errorf("open /home/alice/public_html/x.php: %w", os.ErrNotExist)
	err = fileResponseSourceError(missing)
	if !errors.Is(err, errFileResponseRefused) || !errors.Is(err, os.ErrNotExist) || err.Error() != missing.Error() {
		t.Errorf("source refusal = %q, refused=%v", err, errors.Is(err, errFileResponseRefused))
	}
	if err := fileResponseSourceError(os.ErrPermission); errors.Is(err, errFileResponseRefused) {
		t.Errorf("permission failure classified as refusal: %q", err)
	}
}
