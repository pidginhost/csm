package checks

import (
	"context"
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
