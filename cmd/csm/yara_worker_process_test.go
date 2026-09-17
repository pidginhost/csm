package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/yaraworker"
)

// Run the real worker entry point in a child test process, including its
// config loading. Argument-recording helpers cannot catch config fallback.
func TestYaraWorkerProcess(t *testing.T) {
	if os.Getenv("CSM_TEST_YARA_WORKER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			runYaraWorker()
			return
		}
	}
	t.Fatal("missing worker arguments")
}

func TestSupervisedYaraWorkerKeepsConfigDir(t *testing.T) {
	for _, envDir := range []string{"missing", "invalid-fragment"} {
		t.Run(envDir, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "csm.yaml")
			if err := os.WriteFile(configPath, []byte("{}\n"), 0600); err != nil {
				t.Fatal(err)
			}
			selectedDir := filepath.Join(dir, "selected")
			fallbackDir := filepath.Join(dir, "environment")
			if envDir == "invalid-fragment" {
				if err := os.Mkdir(fallbackDir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(fallbackDir, "bad.yaml"), []byte("[invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("CSM_CONFIG_DIR", fallbackDir)
			t.Setenv("CSM_TEST_YARA_WORKER", "1")
			executable, exeErr := os.Executable()
			if exeErr != nil {
				t.Fatal(exeErr)
			}
			t.Setenv("CSM_TEST_EXECUTABLE", executable)
			worker := filepath.Join(dir, "worker")
			if err := os.WriteFile(worker, []byte("#!/bin/sh\nexec \"$CSM_TEST_EXECUTABLE\" -test.run=^TestYaraWorkerProcess$ -- \"$@\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			sup, err := yaraworker.NewSupervisor(yaraworker.SupervisorConfig{
				BinaryPath: worker, SocketPath: filepath.Join(dir, "worker.sock"),
				ConfigFile: configPath, ConfigDir: selectedDir,
				RulesDir: filepath.Join(dir, "rules"), StartTimeout: 3 * time.Second,
				MinRestartInterval: 10 * time.Millisecond, MaxRestartInterval: 20 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = sup.Stop() })
			if err := sup.Start(context.Background()); err != nil {
				t.Fatalf("worker re-selected config instead of allowing missing inherited directory: %v", err)
			}
			// A later creation and removal must keep the same selection on
			// both restarts, including when an environment override is set.
			for _, present := range []bool{true, false} {
				if present {
					if err := os.Mkdir(selectedDir, 0700); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Remove(selectedDir); err != nil {
					t.Fatal(err)
				}
				pid := sup.ChildPID()
				if err := sup.RestartWorker(); err != nil {
					t.Fatal(err)
				}
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					if next := sup.ChildPID(); next != 0 && next != pid && sup.Reload() == nil {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if next := sup.ChildPID(); next == 0 || next == pid {
					t.Fatalf("worker did not restart with directory present=%t", present)
				}
				if err := sup.Reload(); err != nil {
					t.Fatalf("worker unavailable with directory present=%t: %v", present, err)
				}
			}
		})
	}
}

func TestYaraWorkerExplicitMissingConfigDirIsRejected(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	_, err := resolveConfDirFromArgs([]string{"csm", "yara-worker", "--config-dir", missing})
	if err == nil || !strings.Contains(err.Error(), "--config-dir refused") {
		t.Fatalf("explicit missing directory error = %v", err)
	}
}
