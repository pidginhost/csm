package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func withVirtualPatchCLISeams(t *testing.T) {
	t.Helper()
	oldLoad := virtualPatchLoadConfig
	oldEUID := virtualPatchEUID
	oldTimeout := virtualPatchTimeout
	oldScan := virtualPatchScan
	oldApply := virtualPatchApply
	t.Cleanup(func() {
		virtualPatchLoadConfig = oldLoad
		virtualPatchEUID = oldEUID
		virtualPatchTimeout = oldTimeout
		virtualPatchScan = oldScan
		virtualPatchApply = oldApply
	})
	virtualPatchLoadConfig = func() *config.Config {
		cfg := &config.Config{}
		cfg.AutoResponse.VirtualPatchExposedFiles = config.VirtualPatchManual
		return cfg
	}
	virtualPatchEUID = func() int { return 0 }
}

func TestRunVirtualPatchCommandRequiresRootBeforeScan(t *testing.T) {
	for _, args := range [][]string{nil, {"--apply"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			withVirtualPatchCLISeams(t)
			virtualPatchEUID = func() int { return 1000 }
			scanned := false
			virtualPatchScan = func(context.Context, *config.Config) []alert.Finding {
				scanned = true
				return nil
			}
			var stderr bytes.Buffer
			if code := runVirtualPatchCommand(args, &stderr); code != 1 {
				t.Fatalf("exit code = %d, want 1", code)
			}
			if scanned {
				t.Fatal("non-root command should fail before the expensive scan")
			}
			if !strings.Contains(stderr.String(), "must run as root") {
				t.Fatalf("missing root error: %s", stderr.String())
			}
		})
	}
}

func TestRunVirtualPatchCommandProcessesConfirmedPartialResults(t *testing.T) {
	withVirtualPatchCLISeams(t)
	virtualPatchTimeout = time.Millisecond
	want := alert.Finding{Check: "web_exposed_config_leak", FilePath: filepath.Join(t.TempDir(), ".env")}
	virtualPatchScan = func(ctx context.Context, _ *config.Config) []alert.Finding {
		<-ctx.Done()
		return []alert.Finding{want}
	}
	applied := false
	virtualPatchApply = func(_ *config.Config, findings []alert.Finding, apply bool) []alert.Finding {
		if apply && len(findings) == 1 && findings[0].FilePath == want.FilePath {
			applied = true
		}
		return []alert.Finding{{Message: "VIRTUAL-PATCH: denied HTTP access to " + want.FilePath}}
	}
	var stderr bytes.Buffer
	if code := runVirtualPatchCommand([]string{"--apply"}, &stderr); code != 1 {
		t.Fatalf("timed-out scan exit code = %d, want 1", code)
	}
	if !applied {
		t.Fatal("confirmed results returned before timeout were not applied")
	}
	if !strings.Contains(stderr.String(), "Scan incomplete") {
		t.Fatalf("timeout was not reported: %s", stderr.String())
	}
}

func TestRunVirtualPatchCommandReturnsFailureWhenAnActionFails(t *testing.T) {
	withVirtualPatchCLISeams(t)
	virtualPatchScan = func(context.Context, *config.Config) []alert.Finding {
		return []alert.Finding{{Check: "web_exposed_config_leak", FilePath: "/home/a/.env"}}
	}
	virtualPatchApply = func(*config.Config, []alert.Finding, bool) []alert.Finding {
		return []alert.Finding{{Message: "VIRTUAL-PATCH failed: /home/a/.env"}}
	}
	var stderr bytes.Buffer
	if code := runVirtualPatchCommand([]string{"--apply"}, &stderr); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if strings.Contains(stderr.String(), "Rollback records saved") {
		t.Fatalf("failure incorrectly claimed a rollback backup: %s", stderr.String())
	}
}
