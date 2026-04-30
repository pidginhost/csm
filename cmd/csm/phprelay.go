package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/pidginhost/csm/internal/control"
)

func runPHPRelay() {
	args := os.Args[2:]
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: csm phprelay <status|ignore-script|unignore|ignore-list|dry-run|thaw>")
		os.Exit(1)
	}
	if err := dispatchPHPRelay(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func dispatchPHPRelay(args []string) error {
	switch args[0] {
	case "status":
		return phpRelayStatus()
	case "ignore-script":
		return phpRelayIgnoreScript(args[1:])
	case "unignore":
		return phpRelayUnignore(args[1:])
	case "ignore-list":
		return phpRelayIgnoreList()
	case "dry-run":
		return phpRelayDryRun(args[1:])
	case "thaw":
		return phpRelayThaw(args[1:])
	}
	return fmt.Errorf("unknown phprelay subcommand %q", args[0])
}

func phpRelayStatus() error {
	raw := requireDaemon(control.CmdPHPRelayStatus, control.PHPRelayStatusRequest{})
	var resp control.PHPRelayStatusResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decoding status: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(resp)
}

func phpRelayIgnoreScript(args []string) error {
	fs := flag.NewFlagSet("ignore-script", flag.ContinueOnError)
	forHours := fs.Int("for-hours", 24*7, "TTL in hours")
	persist := fs.Bool("persist", false, "Persist to bbolt")
	reason := fs.String("reason", "", "Free-form reason")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return errors.New("usage: csm phprelay ignore-script <scriptKey> [--for-hours N] [--persist] [--reason ...]")
	}
	raw := requireDaemon(control.CmdPHPRelayIgnoreScript, control.PHPRelayIgnoreScriptRequest{
		ScriptKey: rest[0], ForHours: *forHours, Persist: *persist, Reason: *reason,
		AddedBy: os.Getenv("USER"),
	})
	var resp control.PHPRelayIgnoreScriptResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decoding ignore-script: %w", err)
	}
	fmt.Printf("ignored until %s\n", resp.ExpiresAt.Format(time.RFC3339))
	return nil
}

func phpRelayUnignore(args []string) error {
	fs := flag.NewFlagSet("unignore", flag.ContinueOnError)
	persist := fs.Bool("persist", false, "Also remove from bbolt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return errors.New("usage: csm phprelay unignore <scriptKey> [--persist]")
	}
	_ = requireDaemon(control.CmdPHPRelayUnignore, control.PHPRelayUnignoreRequest{ScriptKey: rest[0], Persist: *persist})
	return nil
}

func phpRelayIgnoreList() error {
	raw := requireDaemon(control.CmdPHPRelayIgnoreList, struct{}{})
	var resp control.PHPRelayIgnoreListResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decoding ignore-list: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(resp)
}

func phpRelayDryRun(args []string) error {
	fs := flag.NewFlagSet("dry-run", flag.ContinueOnError)
	persist := fs.Bool("persist", false, "Write override to bbolt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 || (rest[0] != "on" && rest[0] != "off" && rest[0] != "reset") {
		return errors.New("usage: csm phprelay dry-run on|off|reset [--persist]")
	}
	raw := requireDaemon(control.CmdPHPRelayDryRun, control.PHPRelayDryRunRequest{Mode: rest[0], Persist: *persist})
	var resp control.PHPRelayDryRunResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decoding dry-run: %w", err)
	}
	fmt.Printf("effective dry-run: %v (source: %s)\n", resp.Effective, resp.Source)
	return nil
}

func phpRelayThaw(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: csm phprelay thaw <msgID>")
	}
	if _, err := strconv.Atoi(args[0]); err == nil {
		return errors.New("msg_id looks numeric; pass the full Exim msg ID")
	}
	raw := requireDaemon(control.CmdPHPRelayThaw, control.PHPRelayThawRequest{MsgID: args[0], By: os.Getenv("USER")})
	var resp control.PHPRelayThawResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decoding thaw: %w", err)
	}
	if resp.Stderr != "" {
		fmt.Fprintln(os.Stderr, resp.Stderr)
	}
	return nil
}
