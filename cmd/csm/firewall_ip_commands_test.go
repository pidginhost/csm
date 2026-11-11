package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/control"
)

// runCLI runs fn with os.Args set to args and returns what it printed.
func runCLI(t *testing.T, args []string, fn func()) string {
	t.Helper()
	out, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	savedArgs, savedOut := os.Args, os.Stdout
	os.Args, os.Stdout = args, out
	defer func() { os.Args, os.Stdout = savedArgs, savedOut }()
	fn()
	data, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestFirewallIPCommandsSendTheirRequest(t *testing.T) {
	cases := []struct {
		args []string
		cmd  string
		want control.FirewallIPArgs
	}{
		{[]string{"deny", "192.0.2.10"}, control.CmdFirewallBlock, control.FirewallIPArgs{IP: "192.0.2.10", Reason: "Blocked via CLI"}},
		{[]string{"deny", "192.0.2.10", "--config", "/etc/csm/csm.yaml", "bad", "actor"}, control.CmdFirewallBlock, control.FirewallIPArgs{IP: "192.0.2.10", Reason: "bad actor"}},
		{[]string{"allow", "2001:db8::1"}, control.CmdFirewallAllow, control.FirewallIPArgs{IP: "2001:db8::1", Reason: "Allowed via CLI"}},
		{[]string{"allow", "198.51.100.7", "office"}, control.CmdFirewallAllow, control.FirewallIPArgs{IP: "198.51.100.7", Reason: "office"}},
		{[]string{"tempban", "192.0.2.11", "7d", "spam", "run"}, control.CmdFirewallTempBan, control.FirewallIPArgs{IP: "192.0.2.11", Reason: "spam run", Timeout: "168h0m0s"}},
		{[]string{"tempban", "192.0.2.11", "1h30m"}, control.CmdFirewallTempBan, control.FirewallIPArgs{IP: "192.0.2.11", Reason: "Tempban via CLI", Timeout: "1h30m0s"}},
		{[]string{"tempallow", "203.0.113.5", "30m"}, control.CmdFirewallTempAllow, control.FirewallIPArgs{IP: "203.0.113.5", Reason: "Temp allow via CLI", Timeout: "30m0s"}},
		{[]string{"tempallow", "203.0.113.5", "1d", "vendor"}, control.CmdFirewallTempAllow, control.FirewallIPArgs{IP: "203.0.113.5", Reason: "vendor", Timeout: "24h0m0s"}},
	}
	for _, tc := range cases {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			var calls int
			cleanup := fakeDaemon(t, func(req control.Request) control.Response {
				calls++
				var got control.FirewallIPArgs
				if err := json.Unmarshal(req.Args, &got); err != nil || req.Cmd != tc.cmd || got != tc.want {
					t.Errorf("request %s %+v (%v), want %s %+v", req.Cmd, got, err, tc.cmd, tc.want)
				}
				return control.Response{OK: true, Result: json.RawMessage(`{"message":"done ` + req.Cmd + `"}`)}
			})
			defer cleanup()
			out := runCLI(t, append([]string{"csm", "firewall"}, tc.args...), runFirewall)
			if want := "done " + tc.cmd + "\n"; out != want || calls != 1 {
				t.Fatalf("output %q after %d calls, want %q after 1", out, calls, want)
			}
		})
	}
}

func TestFirewallFileCommandsSendBatches(t *testing.T) {
	var list strings.Builder
	list.WriteString("# blocklist\n\n")
	for i := 0; i < 1001; i++ {
		fmt.Fprintf(&list, "198.51.100.%d # entry %d\n", i%250, i)
	}
	path := filepath.Join(t.TempDir(), "ips.txt")
	if err := os.WriteFile(path, []byte(list.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		verb, cmd, reason, reply, want string
	}{
		{"deny-file", control.CmdFirewallDenyFile, "Bulk block via CLI", "Blocked %d, skipped 0 invalid", "Blocked 1001, skipped 0 invalid\n"},
		{"allow-file", control.CmdFirewallAllowFile, "Bulk allow via CLI", "Allowed %d, failed 1, skipped 2 invalid", "Allowed 1001, failed 2, skipped 4 invalid\n"},
	}
	for _, tc := range cases {
		t.Run(tc.verb, func(t *testing.T) {
			var sizes []int
			cleanup := fakeDaemon(t, func(req control.Request) control.Response {
				var got control.FirewallFileArgs
				if err := json.Unmarshal(req.Args, &got); err != nil || req.Cmd != tc.cmd || got.Reason != tc.reason || got.IPs[0] != "198.51.100."+fmt.Sprint(len(sizes)*1000%250) {
					t.Errorf("request %s reason %q first %v (%v)", req.Cmd, got.Reason, got.IPs[:1], err)
				}
				sizes = append(sizes, len(got.IPs))
				msg, _ := json.Marshal(control.FirewallAckResult{Message: fmt.Sprintf(tc.reply, len(got.IPs))})
				return control.Response{OK: true, Result: msg}
			})
			defer cleanup()
			out := runCLI(t, []string{"csm", "firewall", tc.verb, path}, runFirewall)
			if out != tc.want || fmt.Sprint(sizes) != "[1000 1]" {
				t.Fatalf("output %q with batches %v, want %q with [1000 1]", out, sizes, tc.want)
			}
		})
	}
}

// TestFirewallIPCommandErrors runs each case in a child process because the
// commands exit on bad input. Nothing reaches a daemon.
func TestFirewallIPCommandErrors(t *testing.T) {
	if raw := os.Getenv("CSM_TEST_CLI_ARGS"); raw != "" {
		var args []string
		if err := json.Unmarshal([]byte(raw), &args); err != nil {
			t.Fatal(err)
		}
		os.Args = args
		switch args[1] {
		case "enable":
			runPHPShieldSwitch("enable", (*Installer).EnablePHPShield)
		case "disable":
			runPHPShieldSwitch("disable", (*Installer).DisablePHPShield)
		default:
			runFirewall()
		}
		os.Exit(0)
	}
	missing := filepath.Join(t.TempDir(), "missing.txt")
	cases := []struct {
		args           []string
		exit           int
		stdout, stderr string
	}{
		{[]string{"firewall", "deny"}, 1, "", "Usage: csm firewall deny <ip> [reason]\n"},
		{[]string{"firewall", "deny", "--help"}, 0, "Usage: csm firewall deny <ip> [reason]\n", ""},
		{[]string{"firewall", "deny", "192.0.2.1", "--force"}, 1, "", "reason argument looks like a flag: --force\n"},
		{[]string{"firewall", "allow", "not-an-ip"}, 1, "", "Invalid IP address: not-an-ip\n"},
		{[]string{"firewall", "allow", "help"}, 0, "Usage: csm firewall allow <ip> [reason]\n", ""},
		{[]string{"firewall", "tempban", "192.0.2.1"}, 1, "", "Usage: csm firewall tempban <ip> <duration> [reason]\n  Duration examples: 1h, 24h, 7d, 1h30m\n"},
		{[]string{"firewall", "tempban", "192.0.2.1", "0d"}, 1, "", "Invalid duration '0d': invalid day count\n"},
		{[]string{"firewall", "tempban", "-h"}, 0, "Usage: csm firewall tempban <ip> <duration> [reason]\n", ""},
		{[]string{"firewall", "tempallow", "192.0.2.1"}, 1, "", "Usage: csm firewall tempallow <ip> <duration> [reason]\n  Duration examples: 4h, 1d, 30m\n"},
		{[]string{"firewall", "tempallow", "bad", "1h"}, 1, "", "Invalid IP address: bad\n"},
		{[]string{"firewall", "deny-file"}, 1, "", "Usage: csm firewall deny-file <path>\n  File format: one IP per line, optional # comment\n"},
		{[]string{"firewall", "allow-file"}, 1, "", "Usage: csm firewall allow-file <path>\n  File format: one IP per line, optional # comment\n"},
		{[]string{"firewall", "allow-file", missing}, 1, "", "opening file: open " + missing + ": no such file or directory\n"},
		{[]string{"enable", "--config", missing}, 1, "", "Usage: csm enable --php-shield [--config <path>]\n"},
		{[]string{"disable", "--config", missing}, 1, "", "Usage: csm disable --php-shield [--config <path>]\n"},
	}
	for _, tc := range cases {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			raw, err := json.Marshal(append([]string{"csm"}, tc.args...))
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestFirewallIPCommandErrors$")
			cmd.Env = append(os.Environ(), "CSM_TEST_CLI_ARGS="+string(raw))
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			_ = cmd.Run()
			if code := cmd.ProcessState.ExitCode(); code != tc.exit || stdout.String() != tc.stdout || stderr.String() != tc.stderr {
				t.Fatalf("exit %d, stdout %q, stderr %q; want exit %d, stdout %q, stderr %q",
					code, stdout.String(), stderr.String(), tc.exit, tc.stdout, tc.stderr)
			}
		})
	}
}
