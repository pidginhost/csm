package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/systemdrun"
)

// uapiTimeout bounds one uapi call. cPanel's API binary loads its Perl stack
// and the account's data on every invocation, so several seconds is normal,
// and a hung call must not stall the Exim log watcher for long.
const uapiTimeout = 20 * time.Second

// cPanel ships uapi here; the /usr/bin symlink is not present on every host
// and the service PATH is minimal, so the absolute path is used.
const uapiPath = "/usr/local/cpanel/bin/uapi"

// uapiExec runs cPanel's uapi with the given arguments and returns its
// JSON stdout. A var so tests can observe calls without cPanel.
var uapiExec = func(ctx context.Context, args ...string) ([]byte, error) {
	return runUAPI(ctx, exec.LookPath, uapiCommand, args...)
}

func uapiCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	// #nosec G204 -- name is the resolved systemd-run path or uapi; args are
	// fixed API words plus a cPanel-managed account and an authenticated Exim
	// identity. No shell interprets them; systemdrun escapes variable expansion.
	cmd := exec.CommandContext(ctx, name, args...)
	// Killing systemd-run or uapi need not close pipes inherited by children.
	// Bound the drain too, so those children cannot stall the log watcher.
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
		err = fmt.Errorf("%w: %s", err, truncateDaemon(strings.TrimSpace(string(exitErr.Stderr)), 200))
	}
	return out, err
}

// runUAPI starts uapi as a transient unit forked by PID 1. uapi writes the
// suspension markers under the account home and into cPanel's own caches,
// which the daemon's sandbox does not grant; where systemd-run is unavailable
// the command runs directly.
func runUAPI(ctx context.Context, lookPath systemdrun.LookPathFunc, run systemdrun.RunnerFunc, args ...string) ([]byte, error) {
	opt := systemdrun.Options{Pipe: true}
	if deadline, ok := ctx.Deadline(); ok {
		opt.RuntimeMax = time.Until(deadline)
	}
	return systemdrun.Run(ctx, lookPath, run, opt, uapiPath, args...)
}

// uapiValue encodes v for uapi's command line, which URI-decodes every value:
// a + or % in a mailbox would otherwise reach cPanel as something else. A
// space goes in as %20, which reads the same whether or not the decoder takes
// + for a space.
func uapiValue(v string) string {
	return strings.ReplaceAll(url.QueryEscape(v), "+", "%20")
}

// uapiResultError reads the outcome of a `uapi --output=json` call. uapi exits
// non-zero on an API failure, so the JSON status is the source of truth and
// the exit error only adds context when no reply can be read.
func uapiResultError(out []byte) error {
	var reply struct {
		Result struct {
			Status int      `json:"status"`
			Errors []string `json:"errors"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out, &reply); err != nil {
		return fmt.Errorf("unreadable uapi reply: %s", truncateDaemon(strings.TrimSpace(string(out)), 200))
	}
	if reply.Result.Status == 1 {
		return nil
	}
	if len(reply.Result.Errors) == 0 {
		return errors.New("uapi reported failure without an error message")
	}
	return errors.New(strings.Join(reply.Result.Errors, "; "))
}

// maybeSuspendMailbox stops one abused credential seen sending: it suspends
// the mailbox's logins, which also ends its SMTP authentication, and its
// outgoing mail. It returns true when sending from the mailbox was stopped.
func maybeSuspendMailbox(cfg *config.Config, mailbox, check, reason string) bool {
	stopped, _ := respondToCompromise(cfg, mailboxCompromise{
		Subject: mailbox, Check: check, Reason: reason, Evidence: evidenceSending, At: time.Now(),
	})
	return stopped
}

// cpanelMailBackend suspends through cPanel's uapi and whmapi1.
type cpanelMailBackend struct{}

func (cpanelMailBackend) name() string { return "cpanel" }

func (cpanelMailBackend) suspend(c mailboxCompromise) (store.MailboxSuspension, error) {
	switch {
	case strings.Contains(c.Subject, "@"):
		return suspendCPanelMailbox(c)
	case c.Evidence == evidenceLogin:
		// A cracked login names a mailbox or the account itself, never a
		// domain: login evidence must not reach a domain-wide hold.
		return holdBareCPanelAccount(c.Subject)
	case strings.Contains(c.Subject, "."):
		// A domain names its owning account; only the account hold fits.
		return holdOwnerAccount(c.Subject)
	default:
		return holdBareCPanelAccount(c.Subject)
	}
}

// release undoes exactly what was applied, last first. The first failure
// stops it, so a retry repeats only what is still in place.
func (cpanelMailBackend) release(rec store.MailboxSuspension, actor string) error {
	for i := len(rec.Applied) - 1; i >= 0; i-- {
		var err error
		switch part := rec.Applied[i]; part {
		case store.AppliedSuspendLogin, store.AppliedSuspendOutgoing:
			err = runMailboxRelease(rec.Account, rec.Subject, "un"+part, actor)
		case store.AppliedHoldOutgoing:
			err = releaseCPanelAccountHold(rec.Account, rec.Subject, actor)
		default:
			err = fmt.Errorf("unknown suspension part %q", part)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// active reads cPanel's live state: the outgoing hold list for account holds
// and one mailbox listing per account for mailbox suspensions. A record whose
// status could not be read is left out of the map.
func (cpanelMailBackend) active(recs []store.MailboxSuspension) (map[string]bool, error) {
	live := make(map[string]bool, len(recs))
	byAccount := map[string][]store.MailboxSuspension{}
	for _, r := range recs {
		if r.Kind == store.SuspensionKindAccount {
			live[r.ID] = userOnOutgoingMailHold(r.Account)
			continue
		}
		byAccount[r.Account] = append(byAccount[r.Account], r)
	}
	var errs []error
	for account, rows := range byAccount {
		flags, err := cpanelMailboxFlags(account)
		if err != nil {
			errs = append(errs, fmt.Errorf("mailbox status for cPanel account %s: %w", account, err))
			continue
		}
		for _, r := range rows {
			f, listed := flags[strings.ToLower(r.Subject)]
			live[r.ID] = listed && f.stillApplied(r.Applied)
		}
	}
	return live, errors.Join(errs...)
}

// mailboxFlags is a mailbox's suspension state as cPanel reports it.
type mailboxFlags struct{ login, outgoing bool }

func (f mailboxFlags) stillApplied(applied []string) bool {
	for _, part := range applied {
		if part == store.AppliedSuspendLogin && f.login || part == store.AppliedSuspendOutgoing && f.outgoing {
			return true
		}
	}
	return false
}

// cpanelFlag reads a cPanel 0/1 flag sent as a number, a string or a bool.
type cpanelFlag bool

func (f *cpanelFlag) UnmarshalJSON(b []byte) error {
	switch strings.Trim(string(b), `"`) {
	case "1", "true":
		*f = true
	case "0", "false", "", "null":
		*f = false
	default:
		return fmt.Errorf("unexpected cPanel flag %s", b)
	}
	return nil
}

// cpanelMailboxFlags lists one account's mailboxes with their suspensions.
// get_restrictions=1 makes cPanel include the outgoing suspension flag.
func cpanelMailboxFlags(account string) (map[string]mailboxFlags, error) {
	ctx, cancel := context.WithTimeout(context.Background(), uapiTimeout)
	defer cancel()
	out, execErr := uapiExec(ctx, "--output=json", "--user="+account, "Email", "list_pops_with_disk", "get_restrictions=1")
	if err := uapiResultError(out); err != nil {
		if execErr != nil {
			err = fmt.Errorf("%w: %v", execErr, err)
		}
		return nil, err
	}
	var reply struct {
		Result struct {
			Data []struct {
				Email             string     `json:"email"`
				SuspendedLogin    cpanelFlag `json:"suspended_login"`
				SuspendedOutgoing cpanelFlag `json:"suspended_outgoing"`
			} `json:"data"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out, &reply); err != nil {
		return nil, fmt.Errorf("unreadable mailbox listing: %w", err)
	}
	flags := make(map[string]mailboxFlags, len(reply.Result.Data))
	for _, m := range reply.Result.Data {
		flags[strings.ToLower(m.Email)] = mailboxFlags{login: bool(m.SuspendedLogin), outgoing: bool(m.SuspendedOutgoing)}
	}
	return flags, nil
}

// runMailboxRelease lifts one uapi Email suspension at an operator's request.
func runMailboxRelease(user, mailbox, fn, actor string) error {
	command, err := runUAPIEmail(user, mailbox, fn)
	rec := actionlog.Record{
		Op:          "operate.release_mailbox",
		Action:      fn,
		Actor:       actionlog.WebUI,
		ActorDetail: actor,
		Target:      mailbox,
		Account:     user,
		Command:     command,
		Result:      actionlog.Applied,
	}
	if err != nil {
		rec.Result, rec.Error = actionlog.Failed, err.Error()
	}
	actionlog.Write(rec)
	return err
}

// releaseCPanelAccountHold lifts an account's outgoing hold at an
// operator's request.
func releaseCPanelAccountHold(user, subject, actor string) error {
	if user == "" {
		return fmt.Errorf("no cPanel account recorded for %s", subject)
	}
	out, err := whmapi1ReleaseExec(user)
	rec := actionlog.Record{
		Op:          "operate.release_mailbox",
		Action:      "release_outgoing_email",
		Actor:       actionlog.WebUI,
		ActorDetail: actor,
		Target:      subject,
		Account:     user,
		Command:     []string{"whmapi1", "release_outgoing_email", "user=" + user},
		Result:      actionlog.Applied,
	}
	if err != nil {
		err = fmt.Errorf("whmapi1 release_outgoing_email for %s: %w: %s", user, err, truncateDaemon(strings.TrimSpace(string(out)), 200))
		rec.Result, rec.Error = actionlog.Failed, err.Error()
	}
	actionlog.Write(rec)
	return err
}

// suspendCPanelMailbox suspends one mailbox's logins and outgoing mail. An
// account-wide hold punishes every mailbox under the account for one stolen
// password, so it is the fallback only for sending evidence, when neither
// suspension applies or no cPanel account owns the mailbox.
func suspendCPanelMailbox(c mailboxCompromise) (store.MailboxSuspension, error) {
	stamp := time.Now().Format("2006-01-02 15:04:05")
	domain := extractDomainFromEmail(c.Subject)
	user := lookupCPanelUser(domain)
	if user == "" {
		if c.Evidence == evidenceLogin {
			return store.MailboxSuspension{}, fmt.Errorf("no cPanel account owns %s", domain)
		}
		fmt.Fprintf(os.Stderr, "[%s] auto-suspend: no cPanel account owns %s, falling back to the account hold\n", stamp, domain)
		return holdOwnerAccount(c.Subject)
	}
	var applied []string
	var errs []error
	for _, fn := range []string{store.AppliedSuspendLogin, store.AppliedSuspendOutgoing} {
		if err := runMailboxSuspension(user, c.Subject, fn, c.Reason); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] auto-suspend: uapi Email %s failed for %s: %v\n", stamp, fn, c.Subject, err)
			errs = append(errs, fmt.Errorf("%s: %w", fn, err))
			continue
		}
		applied = append(applied, fn)
	}
	if len(applied) > 0 {
		fmt.Fprintf(os.Stderr, "[%s] AUTO-SUSPEND: mailbox %s suspended (cPanel user %s)\n", stamp, c.Subject, user)
		return store.MailboxSuspension{Kind: store.SuspensionKindMailbox, Account: user, Applied: applied}, nil
	}
	if c.Evidence == evidenceLogin {
		return store.MailboxSuspension{}, errors.Join(errs...)
	}
	return holdOwnerAccount(c.Subject)
}

// holdOwnerAccount holds outgoing mail for the account owning a domain or a
// mailbox's domain.
func holdOwnerAccount(subject string) (store.MailboxSuspension, error) {
	domain := subject
	if at := strings.LastIndexByte(domain, '@'); at >= 0 {
		domain = domain[at+1:]
	}
	user := lookupCPanelUser(domain)
	if !autoSuspendOutgoingMail(subject) {
		return store.MailboxSuspension{}, fmt.Errorf("outgoing mail hold for %s failed", subject)
	}
	return store.MailboxSuspension{Kind: store.SuspensionKindAccount, Account: user, Applied: []string{store.AppliedHoldOutgoing}}, nil
}

// cpanelUsersDir lists one file per cPanel account. var so tests can point it
// at a fixture.
var cpanelUsersDir = "/var/cpanel/users"

// cpanelUserRe bounds a bare login to a cPanel account name before it reaches
// a path or a whmapi1 argument.
var cpanelUserRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// holdBareCPanelAccount holds the account's outgoing mail when a login named
// the cPanel account itself: that password unlocks every mailbox.
func holdBareCPanelAccount(user string) (store.MailboxSuspension, error) {
	if !cpanelUserRe.MatchString(user) {
		return store.MailboxSuspension{}, fmt.Errorf("%q is not a cPanel account name", user)
	}
	if _, err := os.Stat(filepath.Join(cpanelUsersDir, user)); err != nil {
		return store.MailboxSuspension{}, fmt.Errorf("no cPanel account %s", user)
	}
	if !holdCPanelAccount(user) {
		return store.MailboxSuspension{}, fmt.Errorf("outgoing mail hold for cPanel account %s failed", user)
	}
	return store.MailboxSuspension{Kind: store.SuspensionKindAccount, Account: user, Applied: []string{store.AppliedHoldOutgoing}}, nil
}

// runUAPIEmail runs one uapi Email function on a mailbox and returns the
// argv it ran.
func runUAPIEmail(user, mailbox, fn string) ([]string, error) {
	args := []string{"--output=json", "--user=" + user, "Email", fn, "email=" + uapiValue(mailbox)}
	ctx, cancel := context.WithTimeout(context.Background(), uapiTimeout)
	defer cancel()
	out, execErr := uapiExec(ctx, args...)
	err := uapiResultError(out)
	if err != nil && execErr != nil {
		err = fmt.Errorf("%w: %v", execErr, err)
	}
	return append([]string{uapiPath}, args...), err
}

// runMailboxSuspension applies one uapi Email suspension and records it.
func runMailboxSuspension(user, mailbox, fn, reason string) error {
	command, err := runUAPIEmail(user, mailbox, fn)
	rec := actionlog.Record{
		Op:      "respond.suspend_mailbox",
		Action:  fn,
		Target:  mailbox,
		Account: user,
		Reason:  reason,
		Command: command,
		Undo:    fmt.Sprintf("%s %s Email un%s %s", uapiPath, mailboxShellArg("--user="+user), fn, mailboxShellArg("email="+uapiValue(mailbox))),
		Result:  actionlog.Applied,
	}
	if err != nil {
		rec.Result = actionlog.Failed
		rec.Error = err.Error()
	}
	actionlog.Write(rec)
	return err
}

// Undo is pasted into an operator's shell; the parser's authenticated identity
// guarantee does not make mailbox punctuation safe for shell interpretation.
func mailboxShellArg(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
