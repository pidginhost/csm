package checks

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/config"
)

// Independent baseline fixtures. They are not derived from the production
// maps, so deleting a surviving entry fails here.
var (
	expectedQuarantineMoveChecks = []string{
		"new_php_in_languages", "new_php_in_upgrade", "new_webshell_file", "obfuscated_php",
		"phishing_directory", "phishing_page", "suspicious_php_content", "webshell",
	}
	expectedAutoQuarantineChecks = []string{
		"backdoor_binary", "htaccess_handler_abuse", "new_executable_in_config",
		"new_php_in_languages", "new_php_in_upgrade", "new_webshell_file", "obfuscated_php",
		"phishing_directory", "phishing_page", "signature_match_realtime",
		"suspicious_php_content", "webshell",
	}
	expectedAttackMappings = map[string]attackdb.AttackType{
		"admin_panel_bruteforce":      attackdb.AttackBruteForce,
		"api_auth_failure":            attackdb.AttackBruteForce,
		"api_auth_failure_realtime":   attackdb.AttackBruteForce,
		"backdoor_binary":             attackdb.AttackWebshell,
		"cpanel_file_upload_realtime": attackdb.AttackAuthSuccess,
		"cpanel_login":                attackdb.AttackAuthSuccess,
		"cpanel_login_realtime":       attackdb.AttackAuthSuccess,
		"cpanel_multi_ip_login":       attackdb.AttackCPanelLogin,
		"credential_stuffing":         attackdb.AttackBruteForce,
		"email_auth_failure_realtime": attackdb.AttackBruteForce,
		"exfiltration_paste_site":     attackdb.AttackC2,
		"exim_frozen_realtime":        attackdb.AttackSPAM,
		"fake_kernel_thread":          attackdb.AttackC2,
		"ftp_auth_failure_realtime":   attackdb.AttackBruteForce,
		"ftp_bruteforce":              attackdb.AttackBruteForce,
		"ftp_login":                   attackdb.AttackAuthSuccess,
		"http_claimed_bot_unverified": attackdb.AttackRecon,
		"http_request_flood":          attackdb.AttackRecon,
		"http_scanner_profile":        attackdb.AttackRecon,
		"http_ua_spoof":               attackdb.AttackRecon,
		"ip_reputation":               attackdb.AttackReputation,
		"mail_account_compromised":    attackdb.AttackBruteForce,
		"mail_bruteforce":             attackdb.AttackBruteForce,
		"mail_per_account":            attackdb.AttackSPAM,
		"mail_subnet_spray":           attackdb.AttackBruteForce,
		"new_executable_in_config":    attackdb.AttackWebshell,
		"new_php_in_languages":        attackdb.AttackWebshell,
		"new_php_in_upgrade":          attackdb.AttackWebshell,
		"new_webshell_file":           attackdb.AttackWebshell,
		"obfuscated_php":              attackdb.AttackWebshell,
		"pam_bruteforce":              attackdb.AttackBruteForce,
		"pam_login":                   attackdb.AttackAuthSuccess,
		"phishing_credential_log":     attackdb.AttackPhishing,
		"phishing_directory":          attackdb.AttackPhishing,
		"phishing_iframe":             attackdb.AttackPhishing,
		"phishing_kit_archive":        attackdb.AttackPhishing,
		"phishing_page":               attackdb.AttackPhishing,
		"phishing_php":                attackdb.AttackPhishing,
		"phishing_redirector":         attackdb.AttackPhishing,
		"php_suspicious_execution":    attackdb.AttackC2,
		"smtp_bruteforce":             attackdb.AttackBruteForce,
		"smtp_probe_abuse":            attackdb.AttackBruteForce,
		"smtp_subnet_spray":           attackdb.AttackBruteForce,
		"ssh_login_unknown_ip":        attackdb.AttackBruteForce,
		"suspicious_php_content":      attackdb.AttackWebshell,
		"suspicious_process":          attackdb.AttackC2,
		"user_outbound_connection":    attackdb.AttackC2,
		"webmail_bruteforce":          attackdb.AttackBruteForce,
		"webmail_login_realtime":      attackdb.AttackAuthSuccess,
		"webshell":                    attackdb.AttackWebshell,
		"wp_login_bruteforce":         attackdb.AttackBruteForce,
		"wp_user_enumeration":         attackdb.AttackRecon,
		"xmlrpc_abuse":                attackdb.AttackBruteForce,
	}
)

func sortedSetKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func unregisteredNames(names []string) []string {
	var out []string
	for _, n := range names {
		if _, ok := LookupCheck(n); !ok {
			out = append(out, n)
		}
	}
	return out
}

// Every name a response or attack-mapping table selects must be a
// registered check; a renamed or never-emitted name is inert forever.
func TestResponseTablesNameRegisteredChecks(t *testing.T) {
	tables := map[string][]string{
		"quarantineMoveChecks":   sortedSetKeys(quarantineMoveChecks),
		"autoQuarantineChecks":   sortedSetKeys(autoQuarantineChecks),
		"eligibleFullScanChecks": sortedSetKeys(eligibleFullScanChecks),
		"attackdb.checkToAttack": attackdb.MappedChecks(),
	}
	for table, names := range tables {
		if bad := unregisteredNames(names); len(bad) != 0 {
			t.Errorf("%s names unregistered checks %v", table, bad)
		}
	}
	// A mutated copy with one unregistered name must trip the guard.
	for table, names := range tables {
		mutated := append(append([]string(nil), names...), "php_dropper")
		if bad := unregisteredNames(mutated); !reflect.DeepEqual(bad, []string{"php_dropper"}) {
			t.Errorf("%s: guard does not detect an unregistered name: %v", table, bad)
		}
	}
}

func TestResponseTableMembershipIsPinned(t *testing.T) {
	if got := sortedSetKeys(quarantineMoveChecks); !reflect.DeepEqual(got, expectedQuarantineMoveChecks) {
		t.Errorf("quarantineMoveChecks = %v, want %v", got, expectedQuarantineMoveChecks)
	}
	if got := sortedSetKeys(eligibleFullScanChecks); !reflect.DeepEqual(got, expectedQuarantineMoveChecks) {
		t.Errorf("eligibleFullScanChecks = %v, must equal the manual move set %v", got, expectedQuarantineMoveChecks)
	}
	if got := sortedSetKeys(autoQuarantineChecks); !reflect.DeepEqual(got, expectedAutoQuarantineChecks) {
		t.Errorf("autoQuarantineChecks = %v, want %v", got, expectedAutoQuarantineChecks)
	}
	for _, set := range []map[string]bool{quarantineMoveChecks, autoQuarantineChecks, eligibleFullScanChecks} {
		for name, enabled := range set {
			if !enabled {
				t.Errorf("%s is listed but disabled in a response set", name)
			}
		}
		if set["php_dropper"] || set["php_dropper_realtime"] {
			t.Error("phantom or realtime dropper name present in a response set")
		}
	}
}

func TestAttackMappingIsPinned(t *testing.T) {
	mapped := attackdb.MappedChecks()
	if !sort.StringsAreSorted(mapped) {
		t.Error("MappedChecks() is not sorted")
	}
	got := map[string]attackdb.AttackType{}
	for _, name := range mapped {
		kind, ok := attackdb.AttackTypeFor(name)
		if !ok {
			t.Errorf("%s listed but unmapped", name)
			continue
		}
		got[name] = kind
	}
	if !reflect.DeepEqual(got, expectedAttackMappings) {
		t.Errorf("attack mappings differ from the pinned fixture:\n got  %v\n want %v", got, expectedAttackMappings)
	}
	// php_dropper, modsec_block and waf_block were listed but never emitted;
	// the realtime dropper name must not be added as a substitute.
	for _, phantom := range []string{"php_dropper", "php_dropper_realtime", "modsec_block", "waf_block"} {
		if _, ok := attackdb.AttackTypeFor(phantom); ok {
			t.Errorf("%s must not be mapped", phantom)
		}
	}
	copyOut := attackdb.MappedChecks()
	copyOut[0] = "mutated"
	if attackdb.MappedChecks()[0] == "mutated" {
		t.Error("MappedChecks exposes shared memory")
	}
}

// withResponseRoots points every quarantine path seam at one temp tree: the
// account root for the fixture file and a separate quarantine directory.
func withResponseRoots(t *testing.T) (root, qdir string) {
	t.Helper()
	root, qdir = redirectQuarantineForFullScan(t)
	withAccountHomeRoots(t, root)
	return root, qdir
}

func writeResponseFixture(t *testing.T, root, name string) string {
	t.Helper()
	path := filepath.Join(root, "alice", "public_html", name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("<?php // response fixture\n"), 0o644); err != nil { // #nosec G306 -- docroot fixture
		t.Fatal(err)
	}
	return path
}

func quarantinedFiles(t *testing.T, qdir string) []string {
	t.Helper()
	var out []string
	if err := filepath.Walk(qdir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && !strings.HasSuffix(p, ".meta") {
			out = append(out, p)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// Every surviving manual-move name describes, admits and performs the same
// file move, and the full-scan path performs it too.
func TestQuarantineMoveDispatchPerName(t *testing.T) {
	for _, name := range expectedQuarantineMoveChecks {
		t.Run(name, func(t *testing.T) {
			root, qdir := withResponseRoots(t)
			path := writeResponseFixture(t, root, name+".php")
			if !HasFix(name) {
				t.Fatal("HasFix false")
			}
			if desc := FixDescription(name, "", path); !strings.HasPrefix(desc, "Quarantine "+path) {
				t.Fatalf("FixDescription = %q", desc)
			}
			r := ApplyFix(context.Background(), name, "", "", path)
			if !r.Success || !strings.HasPrefix(r.Action, "quarantined "+path) {
				t.Fatalf("ApplyFix = %+v", r)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("source still present after manual move: %v", err)
			}
			if got := quarantinedFiles(t, qdir); len(got) != 1 {
				t.Fatalf("quarantine holds %v, want one file", got)
			}

			again := writeResponseFixture(t, root, name+"-fullscan.php")
			res, eligible := QuarantineFindingFile(alert.Finding{Check: name, Severity: alert.Critical, FilePath: again})
			if !eligible || !res.Success {
				t.Fatalf("full-scan quarantine = %+v eligible=%v", res, eligible)
			}
			if _, err := os.Stat(again); !os.IsNotExist(err) {
				t.Fatalf("source still present after full-scan move: %v", err)
			}
			low, eligible := QuarantineFindingFile(alert.Finding{Check: name, Severity: alert.High, FilePath: writeResponseFixture(t, root, name+"-high.php")})
			if eligible || low.Success {
				t.Fatalf("full-scan accepted a High finding: %+v", low)
			}
		})
	}
}

// Ordinary automatic names move a Critical file and refuse a lower severity.
// A realtime signature match on these benign small bytes must be rejected.
func TestAutoQuarantineDispatchPerName(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	for _, name := range expectedAutoQuarantineChecks {
		t.Run(name, func(t *testing.T) {
			root, qdir := withResponseRoots(t)
			cfg.StatePath = t.TempDir()
			path := writeResponseFixture(t, root, name+".php")
			actions := AutoQuarantineFiles(cfg, []alert.Finding{{Check: name, Severity: alert.High, FilePath: path}})
			if len(actions) != 0 {
				t.Fatalf("High finding acted: %+v", actions)
			}
			finding := alert.Finding{Check: name, Severity: alert.Critical, FilePath: path, Message: name + " fixture", Details: "Category: webshell\nDescription: fixture"}
			actions = AutoQuarantineFiles(cfg, []alert.Finding{finding})
			if name == "signature_match_realtime" {
				// A benign small file never passes the realtime validation.
				if len(actions) != 0 {
					t.Fatalf("low-confidence realtime match acted: %+v", actions)
				}
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("low-confidence realtime match moved the file: %v", err)
				}
				return
			}
			if len(actions) != 1 || !strings.Contains(actions[0].Message, "AUTO-QUARANTINE") {
				t.Fatalf("actions = %+v, want one quarantine", actions)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("source still present: %v", err)
			}
			if got := quarantinedFiles(t, qdir); len(got) != 1 {
				t.Fatalf("quarantine holds %v, want one file", got)
			}
		})
	}
}

// Accepted realtime matches bypass surgical cleaning, even on a plugin path.
// The comment has high entropy but contains no executable code or encoding.
func TestAutoQuarantineRealtimeAccepted(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	for _, category := range []string{"dropper", "webshell"} {
		t.Run(category, func(t *testing.T) {
			root, qdir := withResponseRoots(t)
			path := writeResponseFixture(t, root, "wp-content/plugins/example/match.php")
			body := "<?php // " + strings.Repeat("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-", 16) + "\n"
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil { // #nosec G306 -- docroot fixture
				t.Fatal(err)
			}
			finding := alert.Finding{Check: "signature_match_realtime", Severity: alert.High, FilePath: path, Details: "Category: " + category}
			if !isHighConfidenceRealtimeMatch(finding, path, nil) || !ShouldCleanInsteadOfQuarantine(path) {
				t.Fatal("fixture must pass realtime validation on a cleaning-eligible path")
			}
			if actions := AutoQuarantineFiles(cfg, []alert.Finding{finding}); len(actions) != 0 {
				t.Fatalf("High finding acted: %+v", actions)
			}
			if data, err := os.ReadFile(path); err != nil || string(data) != body { // #nosec G304 -- test fixture
				t.Fatalf("High finding changed source: %v", err)
			}
			if entries, err := os.ReadDir(qdir); err != nil || len(entries) != 0 {
				t.Fatalf("High finding wrote quarantine entries: %v, %v", entries, err)
			}
			finding.Severity = alert.Critical
			actions := AutoQuarantineFiles(cfg, []alert.Finding{finding})
			if len(actions) != 1 || actions[0].Check != "auto_response" || actions[0].Severity != alert.Critical || !strings.HasPrefix(actions[0].Message, "AUTO-QUARANTINE:") {
				t.Fatalf("accepted realtime match must quarantine directly: %+v", actions)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("source still present: %v", err)
			}
			files := quarantinedFiles(t, qdir)
			if len(files) != 1 || filepath.Dir(files[0]) != qdir {
				t.Fatalf("want one direct quarantine and no pre-clean backup, got %v", files)
			}
			if data, err := os.ReadFile(files[0]); err != nil || string(data) != body { // #nosec G304 -- test fixture
				t.Fatalf("quarantine did not preserve source bytes: %v", err)
			}
			if _, err := os.Stat(files[0] + ".meta"); err != nil {
				t.Fatalf("missing quarantine metadata: %v", err)
			}
		})
	}
}

// Cleaning errors retain the file for review in both scan and automatic
// response paths. Failed backup storage must not escalate to file removal.
func TestResponseCleaningFailurePerName(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	oldStore := storeQuarantineBackup
	storeQuarantineBackup = func(string, []byte, QuarantineMeta, os.FileMode) error { return os.ErrPermission }
	t.Cleanup(func() { storeQuarantineBackup = oldStore })
	for _, name := range expectedQuarantineMoveChecks {
		t.Run(name, func(t *testing.T) {
			root, qdir := withResponseRoots(t)
			cfg.StatePath = t.TempDir()
			path := writeResponseFixture(t, root, "wp-content/plugins/example/main.php")
			finding := alert.Finding{Check: name, Severity: alert.Critical, FilePath: path}
			result, eligible := QuarantineFindingFile(finding)
			if !eligible || result.Success || !strings.Contains(result.Error, "cannot create durable backup") {
				t.Fatalf("full-scan must report cleaning failure: eligible=%v, result=%+v", eligible, result)
			}
			if data, err := os.ReadFile(path); err != nil || string(data) != "<?php // response fixture\n" { // #nosec G304 -- test fixture
				t.Fatalf("full-scan changed source after cleaning error: %v", err)
			}
			if entries, err := os.ReadDir(qdir); err != nil || len(entries) != 0 {
				t.Fatalf("full-scan wrote quarantine entries after cleaning error: %v, %v", entries, err)
			}
			actions := AutoQuarantineFiles(cfg, []alert.Finding{finding})
			if len(actions) != 1 || actions[0].Severity != alert.Warning || !strings.HasPrefix(actions[0].Message, "AUTO-CLEAN failed") || !strings.Contains(actions[0].Details, "cannot create durable backup") {
				t.Fatalf("automatic path must report cleaning failure for manual review: %+v", actions)
			}
			if data, err := os.ReadFile(path); err != nil || string(data) != "<?php // response fixture\n" {
				t.Fatalf("automatic path changed source after cleaning error: %q, %v", data, err)
			}
			if files := quarantinedFiles(t, qdir); len(files) != 0 {
				t.Fatalf("failed cleaner escalated to quarantine: %v", files)
			}

		})
	}
}

// The full-scan path never reaches the actions the manual dispatcher owns:
// kill-and-quarantine, permissions, crontab truncate, spool and htaccess edit.
func TestFullScanExcludesNonMoveActions(t *testing.T) {
	root, _ := withResponseRoots(t)
	for _, name := range []string{
		"backdoor_binary", "new_executable_in_config", "world_writable_php", "group_writable_php",
		"suspicious_crontab", "email_phishing_content", "htaccess_injection", "htaccess_handler_abuse",
	} {
		path := writeResponseFixture(t, root, name+".php")
		res, eligible := QuarantineFindingFile(alert.Finding{Check: name, Severity: alert.Critical, FilePath: path})
		if eligible || res.Success {
			t.Errorf("%s: full-scan quarantine acted: %+v", name, res)
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s: file touched by an excluded action: %v", name, err)
		}
	}
}

// A name no release ever emitted has no response of any kind, even for an
// otherwise eligible Critical finding on a real file.
func TestPhantomNameHasNoResponse(t *testing.T) {
	root, qdir := withResponseRoots(t)
	path := writeResponseFixture(t, root, "phantom.php")
	before, err := os.ReadFile(path) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	const phantom = "php_dropper"
	if HasFix(phantom) {
		t.Error("HasFix true")
	}
	if desc := FixDescription(phantom, "", path); desc != "" {
		t.Errorf("FixDescription = %q", desc)
	}
	r := ApplyFix(context.Background(), phantom, "", "", path)
	if r.Success || r.Error != "no automated fix available for check type 'php_dropper'" {
		t.Errorf("ApplyFix = %+v", r)
	}
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	finding := alert.Finding{Check: phantom, Severity: alert.Critical, FilePath: path, Message: "phantom", Details: "Category: webshell"}
	if actions := AutoQuarantineFiles(cfg, []alert.Finding{finding}); len(actions) != 0 {
		t.Errorf("automatic quarantine acted: %+v", actions)
	}
	if res, eligible := QuarantineFindingFile(finding); eligible || res.Success {
		t.Errorf("full-scan quarantine acted: %+v", res)
	}
	after, err := os.ReadFile(path) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatalf("file missing after phantom response: %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Error("file bytes changed")
	}
	now, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if now.Mode() != info.Mode() {
		t.Errorf("file mode changed: %v -> %v", info.Mode(), now.Mode())
	}
	if got := quarantinedFiles(t, qdir); len(got) != 0 {
		t.Errorf("quarantine holds %v", got)
	}
	if entries, err := os.ReadDir(qdir); err != nil || len(entries) != 0 {
		t.Errorf("quarantine sidecars: %v, error: %v", entries, err)
	}
	if _, ok := attackdb.AttackTypeFor(phantom); ok {
		t.Error("attack database maps the phantom name")
	}
}
