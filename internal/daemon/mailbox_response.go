package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/config"
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

// maybeSuspendMailbox stops one abused credential: it suspends the mailbox's
// logins, which also ends its SMTP authentication, and its outgoing mail. An
// account-wide hold punishes every mailbox under the account for one stolen
// password, so the hold is the fallback only when neither suspension can be
// applied or no cPanel account owns the mailbox. The action honours the same
// master switch and dry-run safety default as the hold. It returns true when
// sending from the mailbox was stopped by either path.
func maybeSuspendMailbox(cfg *config.Config, mailbox, reason string) bool {
	if cfg == nil || !cfg.AutoResponse.Enabled {
		fmt.Fprintf(os.Stderr, "[%s] auto-suspend: would suspend mailbox %s (auto_response disabled)\n",
			time.Now().Format("2006-01-02 15:04:05"), mailbox)
		return false
	}
	if cfg.AutoResponseDryRunEnabled() {
		fmt.Fprintf(os.Stderr, "[%s] auto-suspend: would suspend mailbox %s (dry-run)\n",
			time.Now().Format("2006-01-02 15:04:05"), mailbox)
		actionlog.Write(actionlog.Record{Op: "respond.suspend_mailbox", Target: mailbox, Reason: reason, Result: actionlog.DryRun})
		return false
	}
	return suspendMailbox(mailbox, reason)
}

func suspendMailbox(mailbox, reason string) bool {
	domain := extractDomainFromEmail(mailbox)
	if domain == "" {
		// A bare domain names the whole account; only the account hold fits.
		return autoSuspendOutgoingMail(mailbox)
	}
	user := lookupCPanelUser(domain)
	if user == "" {
		fmt.Fprintf(os.Stderr, "[%s] auto-suspend: no cPanel account owns %s, falling back to the account hold\n",
			time.Now().Format("2006-01-02 15:04:05"), domain)
		return autoSuspendOutgoingMail(mailbox)
	}
	stopped := false
	for _, fn := range []string{"suspend_login", "suspend_outgoing"} {
		if err := runMailboxSuspension(user, mailbox, fn, reason); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] auto-suspend: uapi Email %s failed for %s: %v\n",
				time.Now().Format("2006-01-02 15:04:05"), fn, mailbox, err)
			continue
		}
		stopped = true
	}
	if stopped {
		fmt.Fprintf(os.Stderr, "[%s] AUTO-SUSPEND: mailbox %s suspended (cPanel user %s)\n",
			time.Now().Format("2006-01-02 15:04:05"), mailbox, user)
		return true
	}
	return autoSuspendOutgoingMail(mailbox)
}

// runMailboxSuspension applies one uapi Email suspension and records it.
func runMailboxSuspension(user, mailbox, fn, reason string) error {
	args := []string{"--output=json", "--user=" + user, "Email", fn, "email=" + mailbox}
	ctx, cancel := context.WithTimeout(context.Background(), uapiTimeout)
	defer cancel()
	out, execErr := uapiExec(ctx, args...)
	err := uapiResultError(out)
	if err != nil && execErr != nil {
		err = fmt.Errorf("%w: %v", execErr, err)
	}
	rec := actionlog.Record{
		Op:      "respond.suspend_mailbox",
		Action:  fn,
		Target:  mailbox,
		Account: user,
		Reason:  reason,
		Command: append([]string{uapiPath}, args...),
		Undo:    fmt.Sprintf("%s %s Email un%s %s", uapiPath, mailboxShellArg("--user="+user), fn, mailboxShellArg("email="+mailbox)),
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
