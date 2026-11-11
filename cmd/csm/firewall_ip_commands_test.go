package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/pidginhost/csm/internal/control"
)

// runCLI captures successful command output and rejects unexpected diagnostics.
func runCLI(t *testing.T, args []string, fn func()) string {
	t.Helper()
	out, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	errOut, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = errOut.Close() }()
	savedArgs, savedOut, savedErr := os.Args, os.Stdout, os.Stderr
	os.Args, os.Stdout, os.Stderr = args, out, errOut
	defer func() { os.Args, os.Stdout, os.Stderr = savedArgs, savedOut, savedErr }()
	fn()
	diagnostics, err := os.ReadFile(errOut.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(diagnostics) != 0 {
		t.Errorf("unexpected stderr: %q", diagnostics)
	}
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
		{[]string{"deny", "--config", "unused.yaml", "192.0.2.10", "-"}, control.CmdFirewallBlock, control.FirewallIPArgs{IP: "192.0.2.10", Reason: "-"}},
		{[]string{"allow", "198.51.100.7", "office", "--config", "unused.yaml", "help"}, control.CmdFirewallAllow, control.FirewallIPArgs{IP: "198.51.100.7", Reason: "office help"}},
		{[]string{"tempban", "192.0.2.11", "--config", "unused.yaml", "1h", ""}, control.CmdFirewallTempBan, control.FirewallIPArgs{IP: "192.0.2.11", Reason: "", Timeout: "1h0m0s"}},
		{[]string{"tempallow", "--config", "unused.yaml", "203.0.113.5", "30m", "vendor", "--config", "other.yaml", "access"}, control.CmdFirewallTempAllow, control.FirewallIPArgs{IP: "203.0.113.5", Reason: "vendor access", Timeout: "30m0s"}},
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
	var ips []string
	for i := 0; i < 2001; i++ {
		ip := fmt.Sprintf("2001:db8::%x", i+1)
		if i == 500 || i == 999 {
			ip = "invalid"
		}
		ips = append(ips, ip)
		fmt.Fprintf(&list, " %s # entry %d\n", ip, i)
	}
	path := filepath.Join(t.TempDir(), "ips.txt")
	if err := os.WriteFile(path, []byte(list.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, verb, cmd, reason, want string
		replies                       []string
	}{
		{"deny", "deny-file", control.CmdFirewallDenyFile, "Bulk block via CLI", "Blocked 1999, skipped 2 invalid\n", []string{"Blocked 998, skipped 2 invalid", "Blocked 1000, skipped 0 invalid", "Blocked 1, skipped 0 invalid"}},
		{"deny failures", "deny-file", control.CmdFirewallDenyFile, "Bulk block via CLI", "Blocked 1996, failed 3, skipped 2 invalid\n", []string{"Blocked 997, failed 1, skipped 2 invalid", "Blocked 998, failed 2, skipped 0 invalid", "Blocked 1, skipped 0 invalid"}},
		{"allow", "allow-file", control.CmdFirewallAllowFile, "Bulk allow via CLI", "Allowed 1999, skipped 2 invalid\n", []string{"Allowed 998, skipped 2 invalid", "Allowed 1000, skipped 0 invalid", "Allowed 1, skipped 0 invalid"}},
		{"allow failures", "allow-file", control.CmdFirewallAllowFile, "Bulk allow via CLI", "Allowed 1996, failed 3, skipped 2 invalid\n", []string{"Allowed 997, failed 1, skipped 2 invalid", "Allowed 998, failed 2, skipped 0 invalid", "Allowed 1, skipped 0 invalid"}},
	}
	wantBatches := [][]string{ips[:1000], ips[1000:2000], ips[2000:]}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var sizes []int
			cleanup := fakeDaemon(t, func(req control.Request) control.Response {
				mu.Lock()
				defer mu.Unlock()
				batch := len(sizes)
				if batch >= len(wantBatches) {
					t.Errorf("unexpected extra batch %d", batch)
					return control.Response{OK: true, Result: json.RawMessage(`{"message":""}`)}
				}
				var got control.FirewallFileArgs
				if err := json.Unmarshal(req.Args, &got); err != nil || req.Cmd != tc.cmd || got.Reason != tc.reason || !slices.Equal(got.IPs, wantBatches[batch]) {
					t.Errorf("batch %d: request %s reason %q (%v), IPs match: %v", batch, req.Cmd, got.Reason, err, slices.Equal(got.IPs, wantBatches[batch]))
				}
				sizes = append(sizes, len(got.IPs))
				msg, _ := json.Marshal(control.FirewallAckResult{Message: tc.replies[batch]})
				return control.Response{OK: true, Result: msg}
			})
			defer cleanup()
			out := runCLI(t, []string{"csm", "firewall", tc.verb, "--config", "unused.yaml", path}, runFirewall)
			mu.Lock()
			defer mu.Unlock()
			if out != tc.want || !slices.Equal(sizes, []int{1000, 1000, 1}) {
				t.Fatalf("output %q with batches %v, want %q with [1000 1000 1]", out, sizes, tc.want)
			}
		})
	}
}

func TestFirewallFileCommandsEmptyList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(path, []byte("# no entries\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cleanup := fakeDaemon(t, func(req control.Request) control.Response {
		t.Errorf("empty list sent a daemon request: %s", req.Cmd)
		return control.Response{OK: true, Result: json.RawMessage(`{"message":""}`)}
	})
	defer cleanup()
	for _, tc := range []struct{ verb, want string }{
		{"deny-file", "Blocked 0, skipped 0 invalid\n"},
		{"allow-file", "Allowed 0, skipped 0 invalid\n"},
	} {
		t.Run(tc.verb, func(t *testing.T) {
			if out := runCLI(t, []string{"csm", "firewall", tc.verb, path}, runFirewall); out != tc.want {
				t.Fatalf("output %q, want %q", out, tc.want)
			}
		})
	}
}

func TestPHPShieldSwitchAppliesInstaller(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	for _, verb := range []string{"enable", "disable"} {
		t.Run(verb, func(t *testing.T) {
			calls := 0
			out := runCLI(t, []string{"csm", verb, "--config", path, "--php-shield"}, func() {
				runPHPShieldSwitch(verb, func(inst *Installer) error {
					calls++
					want := Installer{BinaryPath: binaryPath, ConfigPath: path, StatePath: defaultStatePath, LogPath: defaultLogPath, ConfigExplicit: true}
					if *inst != want {
						t.Errorf("installer %+v, want %+v", *inst, want)
					}
					fmt.Println("applied " + verb)
					return nil
				})
			})
			if want := "applied " + verb + "\n"; out != want || calls != 1 {
				t.Fatalf("output %q after %d calls, want %q after 1", out, calls, want)
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
		case "enable", "disable":
			runPHPShieldSwitch(args[1], func(*Installer) error { return errors.New("apply failed") })
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
		{[]string{"enable", "--php-shield", "--config", missing}, 1, "", "Enable failed: apply failed\n"},
		{[]string{"disable", "--php-shield", "--config", missing}, 1, "", "Disable failed: apply failed\n"},
		{[]string{"firewall", "deny", "--config", missing, "-h"}, 0, "Usage: csm firewall deny <ip> [reason]\n", ""},
		{[]string{"firewall", "allow", "--config", missing}, 1, "", "Usage: csm firewall allow <ip> [reason]\n"},
		{[]string{"firewall", "tempban", "192.0.2.1", "--config", missing}, 1, "", "Usage: csm firewall tempban <ip> <duration> [reason]\n  Duration examples: 1h, 24h, 7d, 1h30m\n"},
		{[]string{"firewall", "tempallow", "--config", missing, "--help"}, 0, "Usage: csm firewall tempallow <ip> <duration> [reason]\n", ""},
		{[]string{"firewall", "tempallow", "192.0.2.1", "1h", "--help"}, 1, "", "reason argument looks like a flag: --help\n"},
		{[]string{"firewall", "deny-file", "--help"}, 1, "", "opening file: open --help: no such file or directory\n"},
		{[]string{"firewall", "allow-file", "--help"}, 1, "", "opening file: open --help: no such file or directory\n"},
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
			var exitErr *exec.ExitError
			if err := cmd.Run(); err != nil && !errors.As(err, &exitErr) {
				t.Fatal(err)
			}
			if code := cmd.ProcessState.ExitCode(); code != tc.exit || stdout.String() != tc.stdout || stderr.String() != tc.stderr {
				t.Fatalf("exit %d, stdout %q, stderr %q; want exit %d, stdout %q, stderr %q",
					code, stdout.String(), stderr.String(), tc.exit, tc.stdout, tc.stderr)
			}
		})
	}
}
