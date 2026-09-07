//go:build linux

package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/yara"
)

func TestCoreStagingPreservesContentFindings(t *testing.T) {
	// Isolate the process-global YAML scanner from other tests' rules.
	if os.Getenv("CSM_TEST_CORE_STAGING") != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(executable, "-test.run=^TestCoreStagingPreservesContentFindings$")
		cmd.Env = append(os.Environ(), "CSM_TEST_CORE_STAGING=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("core staging test: %v\n%s", err, output)
		}
		return
	}

	for _, stage := range []string{"wp_6a9e080f774ec", "attacker-chosen"} {
		for _, engine := range []string{"content", "yaml", "yara"} {
			t.Run(stage+"/"+engine, func(t *testing.T) {
				wpPathStatCache.Clear()
				root := filepath.Join(t.TempDir(), "public_html")
				if err := os.MkdirAll(filepath.Join(root, "wp-includes"), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "wp-includes/version.php"), []byte("<?php $wp_version='6.4.10';"), 0644); err != nil {
					t.Fatal(err)
				}
				staging := filepath.Join(root, "wp-content/upgrade", stage)
				ch := make(chan alert.Finding, 16)
				fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
				clean := filepath.Join(staging, "wordpress/wp-login.php")
				fm.analyzeFile(fileEvent{path: clean, fd: writeStagedFile(t, clean, cleanStagedPHP)})
				got := drainFindings(ch)
				if len(got) != 1 || got[0].FilePath != staging || got[0].Severity != alert.Warning {
					t.Fatalf("staging warning = %+v", got)
				}

				body := "<?php system($_GET['cmd']);"
				wantCheck := "webshell_content_realtime"
				switch engine {
				case "yaml":
					useRealtimeRules(t, strings.Replace(realtimeHighRule, "severity: high", "severity: critical", 1))
					body, wantCheck = "<?php echo 'EVIL_MARKER_A';", "signature_match_realtime"
				case "yara":
					previous := yara.Active()
					yara.SetActive(matchingFanotifyYARABackend{})
					t.Cleanup(func() { yara.SetActive(previous) })
					body, wantCheck = cleanStagedPHP, "yara_match_realtime"
				}
				var paths []string
				for _, name := range []string{"one.php", "two.php"} {
					path := filepath.Join(staging, "wordpress/wp-admin", name)
					paths = append(paths, path)
					fm.analyzeFile(fileEvent{path: path, fd: writeStagedFile(t, path, body)})
				}
				got = drainFindings(ch)
				if len(got) != len(paths) {
					t.Fatalf("findings = %+v, want one per malicious file", got)
				}
				for i, f := range got {
					if f.Check != wantCheck || f.Severity != alert.Critical || f.FilePath != paths[i] {
						t.Errorf("finding = %+v, want Critical %s at %s", f, wantCheck, paths[i])
					}
				}
			})
		}
	}
}
