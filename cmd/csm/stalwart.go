package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/stalwartapi"
	"github.com/pidginhost/csm/internal/stalwartsetup"
)

const stalwartSetupUsage = "usage: csm stalwart setup [--dry-run] [--password-file PATH] [--url URL]"

// stalwartSetupDeps is what `csm stalwart setup` reads from the host.
type stalwartSetupDeps struct {
	loadConfig func() (*config.Config, error)
	readStatus func() ([]byte, error)
	detectMTA  func() platform.MTAKind
	webUsers   func() []string
	getenv     func(string) string
	readFile   func(string) ([]byte, error)
	newAPI     func(url, user, password string) stalwartsetup.API
}

func defaultStalwartSetupDeps() stalwartSetupDeps {
	return stalwartSetupDeps{
		loadConfig: tryLoadConfigLite,
		readStatus: func() ([]byte, error) { return sendControl(control.CmdStatus, nil) },
		detectMTA:  platform.DetectMTA,
		webUsers:   func() []string { return platform.Detect().WebServerUsers() },
		getenv:     os.Getenv,
		readFile:   os.ReadFile,
		newAPI: func(url, user, password string) stalwartsetup.API {
			return stalwartapi.New(url, user, password)
		},
	}
}

func runStalwart() {
	if len(os.Args) < 3 || os.Args[2] != "setup" {
		fmt.Fprintln(os.Stderr, stalwartSetupUsage)
		os.Exit(2)
	}
	os.Exit(runStalwartSetup(os.Args[3:], defaultStalwartSetupDeps(), os.Stdout))
}

// runStalwartSetup prepares Stalwart for CSM. It exits 0 when every step is
// done or was left for a stated reason, 1 when a setting is unsafe or a write
// failed, and 2 on a usage, login or host error.
func runStalwartSetup(args []string, deps stalwartSetupDeps, out io.Writer) int {
	fs := flag.NewFlagSet("csm stalwart setup", flag.ContinueOnError)
	fs.SetOutput(out)
	dryRun := fs.Bool("dry-run", false, "show what would change and change nothing")
	passwordFile := fs.String("password-file", "", "read the admin password from the first line of this file")
	apiURL := fs.String("url", "", "Stalwart admin API address (default: stalwart.api_url)")
	var discard string
	fs.StringVar(&discard, "config", "", "config file path")
	fs.StringVar(&discard, "config-dir", "", "conf.d directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(out, stalwartSetupUsage)
		return 2
	}

	if mta := deps.detectMTA(); mta != platform.MTAStalwart {
		name := string(mta)
		if name == "" {
			name = "unknown"
		}
		fmt.Fprintf(out, "This host's mail server is %s, not Stalwart; nothing to set up.\n", name)
		return 2
	}
	cfg, err := deps.loadConfig()
	if err != nil {
		fmt.Fprintf(out, "Cannot load CSM's config: %v\n", err)
		return 2
	}

	user := deps.getenv("STALWART_USER")
	password := deps.getenv("STALWART_PASSWORD")
	if *passwordFile != "" {
		data, readErr := deps.readFile(*passwordFile)
		if readErr != nil {
			fmt.Fprintf(out, "Cannot read the password file %s.\n", *passwordFile)
			return 2
		}
		password, _, _ = strings.Cut(string(data), "\n")
		password = strings.TrimRight(password, "\r")
	}
	if user == "" || password == "" {
		fmt.Fprintln(out, "Set STALWART_USER to a Stalwart admin, and STALWART_PASSWORD or --password-file to its password.")
		return 2
	}
	// Defense in depth: the client never puts the login in an error, but
	// nothing this command prints may carry the password.
	redact := func(s string) string { return strings.ReplaceAll(s, password, "[redacted]") }

	url := cfg.Stalwart.APIURL
	if *apiURL != "" {
		url = *apiURL
	}
	in := stalwartSetupInputs(cfg, deps)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	api := deps.newAPI(url, user, password)
	plan, err := stalwartsetup.Inspect(ctx, api, in)
	if errors.Is(err, stalwartapi.ErrUnauthorized) {
		fmt.Fprintf(out, "Stalwart at %s refused the admin login for %s.\n", url, user)
		return 2
	}
	if err != nil {
		fmt.Fprintf(out, "Cannot read Stalwart's settings at %s: %s\n", url, redact(err.Error()))
		return 1
	}

	if *dryRun {
		printStalwartSteps(out, plan, false)
		fmt.Fprintln(out, "Dry run: nothing was changed.")
		return stalwartSetupExit(plan)
	}
	warnings, err := plan.Apply(ctx, api)
	if err != nil {
		fmt.Fprintf(out, "Setup stopped at %s\n", redact(err.Error()))
		fmt.Fprintln(out, "Changes made before it were applied. Run csm stalwart setup again after fixing the cause.")
		return 1
	}
	printStalwartSteps(out, plan, true)
	for _, w := range warnings {
		fmt.Fprintf(out, "Stalwart reload warning: %s\n", redact(w))
	}
	return stalwartSetupExit(plan)
}

// stalwartSetupInputs reads the running daemon's status for the planner. A
// daemon that cannot be reached manages no lock.
func stalwartSetupInputs(cfg *config.Config, deps stalwartSetupDeps) stalwartsetup.Inputs {
	var automation *health.AutomationStatus
	if raw, err := deps.readStatus(); err == nil {
		var sr control.StatusResult
		if json.Unmarshal(raw, &sr) == nil && sr.Snapshot != nil {
			automation = &sr.Snapshot.Automation
		}
	}
	return stalwartInputs(cfg, deps.webUsers(), automation)
}

// stalwartInputs gathers what the planner needs from CSM. The lock counts
// only when the running daemon reports it: a lock written to the config but
// not loaded protects nothing.
func stalwartInputs(cfg *config.Config, webUsers []string, automation *health.AutomationStatus) stalwartsetup.Inputs {
	in := stalwartsetup.Inputs{WebUsers: webUsers}
	expiry, err := time.ParseDuration(cfg.AutoResponse.BlockExpiry)
	if err != nil || expiry <= 0 {
		expiry, _ = time.ParseDuration(config.DefaultBlockExpiry)
	}
	in.BlockExpiry = expiry
	if automation != nil {
		in.LockManaged = automation.FirewallManaged
		in.LockedPorts = automation.FirewallLocalPortLocks
	}
	return in
}

func printStalwartSteps(out io.Writer, plan stalwartsetup.Plan, applied bool) {
	var b bytes.Buffer
	for _, s := range plan.Steps {
		state := string(s.State)
		if applied && s.State == stalwartsetup.Change {
			state = "changed"
		}
		fmt.Fprintf(&b, "%s: %s: %s\n", s.Name, state, s.Detail)
	}
	_, _ = out.Write(b.Bytes())
}

func stalwartSetupExit(plan stalwartsetup.Plan) int {
	for _, s := range plan.Steps {
		if s.State == stalwartsetup.Unsafe {
			return 1
		}
	}
	return 0
}
