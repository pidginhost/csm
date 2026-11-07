package daemon

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/integrity"
	"github.com/pidginhost/csm/internal/store"
)

func newSignedReloadDaemon(t *testing.T, cfg *config.Config) *Daemon {
	t.Helper()
	dir := t.TempDir()
	binPath := filepath.Join(dir, "bin")
	if err := os.WriteFile(binPath, []byte("stand-in"), 0o600); err != nil {
		t.Fatal(err)
	}
	bh, hashErr := integrity.HashFile(binPath)
	if hashErr != nil {
		t.Fatal(hashErr)
	}
	cfg.Integrity.BinaryHash = bh
	cfgPath := filepath.Join(dir, "csm.yaml")
	confDir := filepath.Join(dir, "conf.d")
	if err := os.Mkdir(confDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confDir, "10-runtime.yaml"), []byte("thresholds:\n  mail_queue_warn: 100\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seedConfigAtPath(t, cfgPath, cfg)
	if _, _, err := integrity.SignConfigFilePreserving(cfgPath, confDir, bh); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.LoadWithDir(cfgPath, confDir)
	if err != nil {
		t.Fatal(err)
	}
	d := newDaemonForReloadTest(t, loaded)
	d.binaryPath = binPath
	if err := integrity.Verify(binPath, loaded); err != nil {
		t.Fatalf("baseline Verify: %v", err)
	}
	return d
}

func appendReloadComment(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, []byte("# operator note\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReloadConfigNoChangeIntegrity(t *testing.T) {
	for _, edit := range []string{"none", "main", "confd"} {
		for _, rehash := range []bool{false, true} {
			name := edit
			if rehash {
				name += "_rehashed"
			}
			t.Run(name, func(t *testing.T) {
				live := false
				cfg := &config.Config{}
				cfg.AutoResponse.DryRun = &live
				d := newSignedReloadDaemon(t, cfg)
				old := d.currentCfg()
				switch edit {
				case "main":
					appendReloadComment(t, old.ConfigFile)
				case "confd":
					appendReloadComment(t, filepath.Join(old.ConfigDir, "10-runtime.yaml"))
				}
				if rehash {
					if _, _, err := integrity.SignConfigFilePreserving(old.ConfigFile, old.ConfigDir, old.Integrity.BinaryHash); err != nil {
						t.Fatal(err)
					}
				}
				before, err := os.Stat(old.ConfigFile)
				if err != nil {
					t.Fatal(err)
				}
				db, err := store.Open(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				prev := store.Global()
				store.SetGlobal(db)
				t.Cleanup(func() {
					store.SetGlobal(prev)
					_ = db.Close()
				})
				db.RecordDryRunBlock("198.51.100.50", "test", time.Hour)
				if db.DryRunBlocksCount() != 1 {
					t.Fatal("dry-run example was not recorded")
				}

				d.reloadConfig()

				if verifyErr := integrity.Verify(d.binaryPath, d.currentCfg()); verifyErr != nil {
					t.Errorf("live Verify after reload: %v", verifyErr)
				}
				if changes := config.Diff(old, d.currentCfg()); len(changes) != 0 {
					t.Errorf("no-change reload altered settings: %v", changes)
				}
				if edit != "none" {
					if verifyErr := integrity.Verify(d.binaryPath, old); verifyErr == nil {
						t.Error("old snapshot should still carry stale hashes after an edit")
					}
				}
				disk, err := config.LoadWithDir(old.ConfigFile, old.ConfigDir)
				if err != nil {
					t.Fatal(err)
				}
				if err := integrity.Verify(d.binaryPath, disk); err != nil {
					t.Errorf("disk Verify after reload: %v", err)
				}
				if edit == "none" {
					if d.currentCfg() != old {
						t.Error("unchanged reload published a config")
					}
					if got := db.DryRunBlocksCount(); got != 1 {
						t.Errorf("unchanged reload purged dry-run examples: %d remain", got)
					}
				}
				if edit == "none" || rehash {
					after, err := os.Stat(old.ConfigFile)
					if err != nil {
						t.Fatal(err)
					}
					if !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
						t.Error("reload rewrote an already signed config")
					}
				}
				select {
				case f := <-d.alertCh:
					t.Errorf("unexpected finding: %s", f.Check)
				default:
				}
			})
		}
	}
}

func TestReloadConfigNoChangeSignFailure(t *testing.T) {
	d := newSignedReloadDaemon(t, &config.Config{})
	old := d.currentCfg()
	appendReloadComment(t, old.ConfigFile)
	// A backup destination that cannot be replaced fails signing even when
	// the test process has privileges to write a read-only directory.
	backup := old.ConfigFile + ".bak"
	if err := os.Rename(backup, backup+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(old.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	metricsBefore := scrapeReloadResults(t)

	d.reloadConfig()

	metricsAfter := scrapeReloadResults(t)
	if metricsAfter[reloadResultError]-metricsBefore[reloadResultError] != 1 || metricsAfter[reloadResultNoop] != metricsBefore[reloadResultNoop] {
		t.Error("failed no-change reload must count as error, not noop")
	}
	if d.currentCfg() != old {
		t.Error("failed signing published a config")
	}
	after, err := os.ReadFile(old.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("failed signing changed the main config")
	}
	f := drainAlert(t, d, time.Second)
	if f.Check != "config_reload_error" || f.Severity != alert.Critical {
		t.Errorf("finding = %s/%s, want Critical config_reload_error", f.Check, f.Severity)
	}
}

func TestReloadConfigQueueFailureKeepsSignedIntegrity(t *testing.T) {
	for _, edit := range []string{"main", "confd", "exemption"} {
		t.Run(edit, func(t *testing.T) {
			var secret [32]byte
			if _, err := rand.Read(secret[:]); err != nil {
				t.Fatal(err)
			}
			t.Setenv("CSM_TEST_RELOAD_HMAC", hex.EncodeToString(secret[:]))
			cfg := &config.Config{}
			// Keep state_path unchanged across reload, but prevent opening a
			// queue below it without depending on permissions or lock timeouts.
			cfg.StatePath = filepath.Join(t.TempDir(), "not-a-directory")
			if err := os.WriteFile(cfg.StatePath, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			d := newSignedReloadDaemon(t, cfg)
			old := d.currentCfg()
			oldExtractor := defaultAccountExtractor.Load()
			t.Cleanup(func() { defaultAccountExtractor.Store(oldExtractor) })
			if err := installAccountExtractorFromConfig(old); err != nil {
				t.Fatal(err)
			}
			extractor := currentAccountExtractor()
			changes := []config.YAMLChange{
				{Path: []string{"alerts", "webhook", "enabled"}, Value: true},
				{Path: []string{"alerts", "webhook", "type"}, Value: "phpanel"},
				{Path: []string{"alerts", "webhook", "url"}, Value: "https://panel.example.com/events"},
				{Path: []string{"alerts", "webhook", "hmac_secret_env"}, Value: "CSM_TEST_RELOAD_HMAC"},
				{Path: []string{"thresholds", "mail_brute_account_key"}, Value: "builtin:postfix-sasl"},
			}
			path := old.ConfigFile
			switch edit {
			case "confd":
				path = filepath.Join(old.ConfigDir, "10-runtime.yaml")
			case "exemption":
				changes = append(changes, config.YAMLChange{Path: []string{"confd"}, Value: map[string]interface{}{"integrity_exempt": []string{"10-runtime.yaml"}}})
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var edited []byte
			if edit == "confd" {
				edited = []byte("alerts:\n  webhook:\n    enabled: true\n    type: phpanel\n    url: https://panel.example.com/events\n    hmac_secret_env: CSM_TEST_RELOAD_HMAC\nthresholds:\n  mail_queue_warn: 100\n  mail_brute_account_key: builtin:postfix-sasl\n")
			} else {
				edited, err = config.YAMLEdit(data, changes)
				if err != nil {
					t.Fatal(err)
				}
			}
			if writeErr := os.WriteFile(path, edited, 0o600); writeErr != nil {
				t.Fatal(writeErr)
			}

			d.reloadConfig()

			f := drainAlert(t, d, time.Second)
			if f.Check != "config_reload_error" || f.Severity != alert.Critical || !strings.Contains(f.Message, "phpanel queue") {
				t.Fatalf("expected queue failure, got %s/%s: %s", f.Check, f.Severity, f.Message)
			}
			if verifyErr := integrity.Verify(d.binaryPath, d.currentCfg()); verifyErr != nil {
				t.Errorf("live Verify after queue failure: %v", verifyErr)
			}
			loaded, err := config.LoadWithDir(old.ConfigFile, old.ConfigDir)
			if err != nil {
				t.Fatal(err)
			}
			if err := integrity.Verify(d.binaryPath, loaded); err != nil {
				t.Errorf("disk Verify after queue failure: %v", err)
			}
			want := *old
			want.Integrity = loaded.Integrity
			want.ConfD = loaded.ConfD
			if !reflect.DeepEqual(d.currentCfg(), &want) {
				t.Error("failed reload must retain settings and adopt only the signed integrity state")
			}
			if currentAccountExtractor() != extractor {
				t.Error("failed reload changed the mail account extractor")
			}
		})
	}
}

func TestReloadConfigWaitsForConfigWriter(t *testing.T) {
	d := newSignedReloadDaemon(t, &config.Config{})
	configMu := integrity.ConfigWriteMutex()
	configMu.Lock()
	locked := true
	defer func() {
		if locked {
			configMu.Unlock()
		}
	}()
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.reloadConfig()
	}()
	select {
	case <-done:
		t.Fatal("reload ran during another config write transaction")
	case <-time.After(150 * time.Millisecond):
	}
	// Finish a save while reload waits. It must read the new live snapshot
	// after acquiring the lock, or it will republish its stale copy.
	old := d.currentCfg()
	appendReloadComment(t, old.ConfigFile)
	if _, _, err := integrity.SignConfigFilePreserving(old.ConfigFile, old.ConfigDir, old.Integrity.BinaryHash); err != nil {
		t.Fatal(err)
	}
	saved, err := config.LoadWithDir(old.ConfigFile, old.ConfigDir)
	if err != nil {
		t.Fatal(err)
	}
	config.SetActive(saved)
	configMu.Unlock()
	locked = false
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reload did not proceed after the config writer finished")
	}
	if d.currentCfg() != saved {
		t.Error("reload republished a snapshot captured before the config writer finished")
	}
}
