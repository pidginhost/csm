package main

import (
	"bufio"
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
	"golang.org/x/term"
)

const stalwartSetupUsage = "usage: csm stalwart setup [--dry-run] [--password-file PATH] [--url URL] [--account-domain NAME]"

// stalwartSetupDeps is what `csm stalwart setup` reads from the host.
type stalwartSetupDeps struct {
	loadConfig func() (*config.Config, error)
	readStatus func() ([]byte, error)
	detectMTA  func() platform.MTAKind
	webUsers   func() []string
	getenv     func(string) string
	readFile   func(string) ([]byte, error)
	// stdin carries the admin login. On a terminal setup asks for it on
	// prompt and reads the password with readHidden, which does not echo.
	stdin         io.Reader
	prompt        io.Writer
	stdinTerminal func() bool
	readHidden    func() ([]byte, error)
	// checkListener refuses an API address another local user may be
	// listening on.
	checkListener func(url string) error
	newAPI        func(url, user, password string) stalwartsetup.API
	// keyAccount returns the account an API key logs in as.
	keyAccount func(ctx context.Context, url, key string) (string, error)
}

func defaultStalwartSetupDeps() stalwartSetupDeps {
	return stalwartSetupDeps{
		loadConfig:    tryLoadConfigLite,
		readStatus:    func() ([]byte, error) { return sendControl(control.CmdStatus, nil) },
		detectMTA:     platform.DetectMTA,
		webUsers:      func() []string { return platform.Detect().WebServerUsers() },
		getenv:        os.Getenv,
		readFile:      os.ReadFile,
		stdin:         os.Stdin,
		prompt:        os.Stderr,
		stdinTerminal: func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		readHidden:    func() ([]byte, error) { return term.ReadPassword(int(os.Stdin.Fd())) },
		checkListener: stalwartapi.CheckListener,
		newAPI: func(url, user, password string) stalwartsetup.API {
			return stalwartapi.NewWithPeerCheck(url, user, password, stalwartapi.CheckPeer)
		},
		keyAccount: func(ctx context.Context, url, key string) (string, error) {
			return stalwartapi.NewKey(url, key, stalwartapi.CheckPeer).SessionAccount(ctx)
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
// done or was left for a stated reason, 1 when a setting is unsafe, CSM's
// response account cannot be set up or a write failed, and 2 on a usage,
// login or host error.
func runStalwartSetup(args []string, deps stalwartSetupDeps, out io.Writer) int {
	var user, password string
	// keys are the API key in the key file and any key setup creates.
	var keys []string
	var output bytes.Buffer
	destination := out
	out = &output
	defer func() {
		text := stalwartapi.Redact(output.String(), user, password)
		for _, k := range keys {
			text = stalwartapi.Redact(text, "", k)
		}
		_, _ = io.WriteString(destination, text)
	}()
	fs := flag.NewFlagSet("csm stalwart setup", flag.ContinueOnError)
	fs.SetOutput(out)
	dryRun := fs.Bool("dry-run", false, "show what would change and change nothing")
	passwordFile := fs.String("password-file", "", "read the admin password from the first line of this file")
	apiURL := fs.String("url", "", "Stalwart admin API address (default: stalwart.api_url)")
	accountDomain := fs.String("account-domain", "", "domain for CSM's service account when Stalwart has several")
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

	if *passwordFile != "" {
		data, readErr := deps.readFile(*passwordFile)
		if readErr != nil {
			fmt.Fprintf(out, "Cannot read the password file %s.\n", *passwordFile)
			return 2
		}
		password, _, _ = strings.Cut(string(data), "\n")
		password = strings.TrimRight(password, "\r")
		if password == "" {
			fmt.Fprintf(out, "The password file %s has an empty first line.\n", *passwordFile)
			return 2
		}
	}
	user, password, err = readStalwartLogin(deps, password)
	if err != nil {
		fmt.Fprintf(out, "Cannot read the Stalwart admin login from stdin: %v\n", err)
		return 2
	}
	if password == "" {
		fmt.Fprintln(out, "No Stalwart admin password: type it when asked, send it on stdin after the user name, or use --password-file.")
		return 2
	}
	// Defense in depth: the client never puts the login in an error, but
	// nothing this command prints may carry the password.
	redact := func(s string) string { return strings.ReplaceAll(s, password, "[redacted]") }

	url := cfg.Stalwart.APIURL
	if *apiURL != "" {
		url = *apiURL
	}
	if addressErr := stalwartapi.ValidateURL(url); addressErr != nil {
		fmt.Fprintln(out, addressErr)
		return 2
	}
	if listenerErr := deps.checkListener(url); listenerErr != nil {
		fmt.Fprintf(out, "Not sending the admin login to %s: %v\n", url, listenerErr)
		return 2
	}
	in := stalwartSetupInputs(cfg, deps)
	in.LocalAPI = stalwartapi.LocalURL(url)
	if !in.LocalAPI {
		in.LockManaged = false
		in.LockedPorts = nil
	}
	in.AccountDomain = *accountDomain
	in.WriteKey = func(secret string) error {
		keys = append(keys, secret)
		return stalwartapi.WriteKeyFile(cfg.Stalwart.APIKeyFile, secret)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// The key works only from this host, so it is never sent anywhere else.
	if in.LocalAPI {
		key, account, keyErr := stalwartKeyAccount(ctx, cfg.Stalwart.APIKeyFile, url, deps.keyAccount)
		if key != "" {
			keys = append(keys, key)
		}
		in.KeyAccount = account
		switch {
		case errors.Is(keyErr, stalwartapi.ErrNoKeyFile), errors.Is(keyErr, stalwartapi.ErrUnauthorized), errors.Is(keyErr, stalwartapi.ErrForbidden):
			// Setup replaces a missing or refused key.
			in.KeyAccount = ""
		case keyErr != nil:
			fmt.Fprintf(out, "Cannot check CSM's Stalwart API key: %s\n", redact(keyErr.Error()))
			return 1
		}
	}
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
		switch {
		case errors.Is(err, stalwartsetup.ErrNotReloaded):
			// A rerun reads the stored settings as done and sends no reload.
			fmt.Fprintln(out, "Stalwart stored the settings but is not using them yet; restart Stalwart to apply them.")
		case errors.Is(err, stalwartsetup.ErrSettingsWrite):
			fmt.Fprintln(out, "Some settings may have been stored. Resolve the error and reload settings in Stalwart before running setup again.")
		default:
			fmt.Fprintln(out, "Resolve the error and run setup again.")
		}
		return 1
	}
	printStalwartSteps(out, plan, true)
	for _, w := range warnings {
		fmt.Fprintf(out, "Stalwart reload warning: %s\n", redact(w))
	}
	return stalwartSetupExit(plan)
}

// defaultStalwartAdmin is the user name setup uses when stdin gives none.
const defaultStalwartAdmin = "admin"

// readStalwartLogin reads the admin user name from stdin, then the password
// unless the password file gave it. An empty user name means admin. On a
// terminal it asks for each and does not echo the password; otherwise it
// reads one line each and prints no prompt.
func readStalwartLogin(deps stalwartSetupDeps, password string) (string, string, error) {
	r := bufio.NewReader(deps.stdin)
	tty := deps.stdinTerminal()
	if tty {
		fmt.Fprintf(deps.prompt, "Stalwart admin user [%s]: ", defaultStalwartAdmin)
	}
	user, err := readStalwartLine(r)
	if err != nil {
		return "", "", err
	}
	user = strings.TrimSpace(user)
	if user == "" {
		user = defaultStalwartAdmin
	}
	if password != "" {
		return user, password, nil
	}
	if !tty {
		password, err = readStalwartLine(r)
		return user, password, err
	}
	fmt.Fprint(deps.prompt, "Stalwart admin password: ")
	secret, err := deps.readHidden()
	fmt.Fprintln(deps.prompt)
	return user, string(secret), err
}

// readStalwartLine reads one line without its line ending. End of input is
// an empty line, not an error.
func readStalwartLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// stalwartKeyAccount reads CSM's key file and asks Stalwart which account the
// key logs in as. A key that was read comes back even when the probe fails,
// so the caller can redact it.
// readStalwartKeyFile reads CSM's API key file; tests replace it.
var readStalwartKeyFile = stalwartapi.ReadKeyFile

func stalwartKeyAccount(ctx context.Context, path, url string, keyAccount func(ctx context.Context, url, key string) (string, error)) (key, account string, err error) {
	key, err = readStalwartKeyFile(path)
	if err != nil {
		return "", "", err
	}
	account, err = keyAccount(ctx, url, key)
	return key, account, err
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
	in := stalwartsetup.Inputs{WebUsers: webUsers, Observe: cfg.ObserveMode()}
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

// stalwartSetupExit is 1 for an unsafe setting, or for a response step left
// as a warning, since CSM then cannot suspend mailboxes or lift bans.
func stalwartSetupExit(plan stalwartsetup.Plan) int {
	for _, s := range plan.Steps {
		if s.State == stalwartsetup.Unsafe || s.State == stalwartsetup.Warn && strings.HasPrefix(s.Name, "response ") {
			return 1
		}
	}
	return 0
}
