package daemon

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// The action log lives beside the SIEM audit log, so an operator who moved
// their log directory gets both streams in the same place.
func TestActionLogPathFollowsTheAuditLogDirectory(t *testing.T) {
	cfg := &config.Config{}
	cfg.Alerts.AuditLog.File.Path = "/srv/logs/csm/audit.jsonl"

	if got, want := actionLogPath(cfg), "/srv/logs/csm/actions.jsonl"; got != want {
		t.Fatalf("action log path = %q, want %q", got, want)
	}
}

func TestActionLogPathFallsBackToThePackagedLogDirectory(t *testing.T) {
	if got, want := actionLogPath(&config.Config{}), filepath.Join(defaultLogDir, "actions.jsonl"); got != want {
		t.Fatalf("action log path = %q, want %q", got, want)
	}
}

func TestStartupRollbackWritesActionBeforeRestart(t *testing.T) {
	const childEnv = "CSM_TEST_STARTUP_ACTION_PHASE"
	phase := os.Getenv(childEnv)
	if phase == "" {
		// Run installs process-wide registries and metrics. A fresh process also
		// proves recovery works without inheriting a sink from another test.
		for _, phase := range []string{"success", "restore-failure"} {
			t.Run(phase, func(t *testing.T) {
				cmd := exec.Command(os.Args[0], "-test.run=^TestStartupRollbackWritesActionBeforeRestart$", "-test.v")
				cmd.Env = append(os.Environ(), childEnv+"="+phase)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("startup subprocess: %v\n%s", err, out)
				}
			})
		}
		return
	}

	root := t.TempDir()
	db, openErr := store.Open(filepath.Join(root, "state"))
	if openErr != nil {
		t.Fatal(openErr)
	}
	store.SetGlobal(db)
	t.Cleanup(func() { store.SetGlobal(nil); _ = db.Close() })
	cfg := &config.Config{ConfigFile: filepath.Join(root, "csm.yaml"), StatePath: filepath.Join(root, "state")}
	cfg.Alerts.AuditLog.File.Path = filepath.Join(root, "logs", "audit.jsonl")
	if phase == "restore-failure" {
		if err := os.Mkdir(cfg.ConfigFile, 0700); err != nil {
			t.Fatal(err)
		}
	} else if err := os.WriteFile(cfg.ConfigFile, []byte("hostname: candidate.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	previous := []byte("hostname: previous.example\n")
	if err := db.SaveFirewallRollback(store.FirewallRollback{PrevYAML: previous, ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}

	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	// A real restart terminates this process, so the evidence must exist when
	// systemctl starts rather than only after startup returns.
	script := "#!/bin/sh\n[ -s \"$CSM_TEST_ACTION_LOG\" ] || exit 23\n: > \"$CSM_TEST_RESTARTED\"\n"
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CSM_TEST_ACTION_LOG", actionLogPath(cfg))
	restarted := filepath.Join(root, "restarted")
	t.Setenv("CSM_TEST_RESTARTED", restarted)
	d := New(cfg, nil, nil, "")
	err := d.Run()
	close(d.stopCh)
	d.wg.Wait()
	if (err != nil) != (phase == "restore-failure") {
		t.Fatalf("startup error=%v, phase=%s", err, phase)
	}
	data, err := os.ReadFile(actionLogPath(cfg))
	if err != nil {
		t.Fatalf("startup rollback has no action log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("startup rollback recorded %d actions, want one", len(lines))
	}
	var rec actionlog.Record
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatal(err)
	}
	want := actionlog.Applied
	if phase == "restore-failure" {
		want = actionlog.Failed
	}
	if rec.Op != "operate.manual_firewall" || rec.Action != "rollback_config" || rec.Result != want || rec.Target != cfg.ConfigFile {
		t.Fatalf("startup rollback record=%+v", rec)
	}
	if phase == "restore-failure" {
		if rec.Error == "" {
			t.Fatal("failed startup rollback omitted its error")
		}
		if _, err := os.Stat(restarted); !os.IsNotExist(err) {
			t.Fatalf("failed restore requested restart: %v", err)
		}
	} else {
		if _, err := os.Stat(restarted); err != nil {
			t.Fatalf("restart was not reached after recording: %v", err)
		}
		if restored, err := os.ReadFile(cfg.ConfigFile); err != nil || string(restored) != string(previous) {
			t.Fatalf("startup did not restore previous config: %v", err)
		}
	}
}

type actionRecords struct{ records []actionlog.Record }

func (s *actionRecords) Write(r actionlog.Record) error { s.records = append(s.records, r); return nil }
func captureActionRecords(t *testing.T) *actionRecords {
	t.Helper()
	s := &actionRecords{}
	actionlog.SetSink(s, "")
	t.Cleanup(func() { actionlog.SetSink(nil, "") })
	return s
}

func TestRollbackActionsIncludeKernelSuccessBeforeStateFailure(t *testing.T) {
	for _, phase := range []string{"success", "nft", "state", "missing"} {
		t.Run(phase, func(t *testing.T) {
			sink := captureActionRecords(t)
			installFakeNft(t)
			path := filepath.Join(t.TempDir(), "rollback.nft")
			if phase != "missing" {
				writeTestFile(t, path, "flush ruleset\n")
			}
			if phase == "nft" {
				t.Setenv("NFT_RESTORE_FAIL", "1")
			}
			if phase == "state" {
				if err := os.Mkdir(firewallStateSnapshotPath(path), 0700); err != nil {
					t.Fatal(err)
				}
			}
			err := applyFirewallRollbackFile(path)
			if (err != nil) != (phase != "success") {
				t.Fatalf("error=%v phase=%s", err, phase)
			}
			if len(sink.records) != 1 {
				t.Fatalf("records=%+v", sink.records)
			}
			r := sink.records[0]
			want := actionlog.Applied
			if phase == "nft" || phase == "missing" {
				want = actionlog.Failed
			}
			if r.Result != want || r.Op != "operate.manual_firewall" || len(r.Command) != 3 || r.Command[2] != path {
				t.Fatalf("record=%+v", r)
			}
			if phase != "success" && strings.TrimSpace(r.Error) == "" {
				t.Fatal("error omitted")
			}
		})
	}
}
