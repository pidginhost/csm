package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/stalwartapi"
	"github.com/pidginhost/csm/internal/store"
)

// stalwartCallTimeout bounds each backend call: suspends run on the log
// reader's path and status reads on a web UI request.
const stalwartCallTimeout = 10 * time.Second

// detectMTA is a var so tests can stand in for the host's mail server.
var detectMTA = platform.DetectMTA

// selectMailBackend picks the mail server CSM suspends mailboxes on. It runs
// once at daemon start, before anything reads the backend.
func selectMailBackend(cfg func() *config.Config) {
	if platform.Detect().IsCPanel() || detectMTA() != platform.MTAStalwart {
		return
	}
	activeMailBackend = stalwartMailBackend{cfg: cfg}
	// The key file is checked on each use, so running setup takes effect
	// without a restart.
	hostHasMailBackend = func() bool { return stalwartKeyPresent(cfg()) }
}

// stalwartMailBackend suspends a Stalwart account by denying it sign-in,
// which also ends its SMTP authentication.
type stalwartMailBackend struct{ cfg func() *config.Config }

func (stalwartMailBackend) name() string { return "stalwart" }

func (b stalwartMailBackend) suspend(c mailboxCompromise) (store.MailboxSuspension, error) {
	if !strings.Contains(c.Subject, "@") {
		return store.MailboxSuspension{}, errors.New("CSM does not suspend Stalwart account names without a domain; change its password in Stalwart")
	}
	client, err := stalwartClient(b.cfg())
	if err != nil {
		return store.MailboxSuspension{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), stalwartCallTimeout)
	defer cancel()
	// DisableSignIn needs the account as read now: a stale permission type
	// would replace the account's whole permission list.
	acct, found, err := client.AccountByAddress(ctx, c.Subject)
	switch {
	case err != nil:
		return store.MailboxSuspension{}, err
	case !found:
		return store.MailboxSuspension{}, fmt.Errorf("no Stalwart account has the address %s; change its password in Stalwart", c.Subject)
	case acct.Admin:
		return store.MailboxSuspension{}, fmt.Errorf("%s is a Stalwart admin account, which CSM does not suspend; change its password in Stalwart", c.Subject)
	case acct.SignInDisabled:
		return store.MailboxSuspension{}, errMailAlreadyRestricted
	}
	err = client.DisableSignIn(ctx, acct)
	var me *stalwartapi.MethodError
	if errors.As(err, &me) && me.Type == "forbidden" {
		// Stalwart refuses a key that lacks one of the account's own
		// permissions, as with a custom admin role.
		err = fmt.Errorf("the CSM key is not allowed to change %s; change its password in Stalwart", c.Subject)
	}
	rec := actionlog.Record{
		Op:      "respond.suspend_mailbox",
		Action:  store.AppliedDisableSignIn,
		Target:  c.Subject,
		Account: acct.ID,
		Reason:  c.Reason,
		Result:  actionlog.Applied,
	}
	if err != nil {
		rec.Result, rec.Error = actionlog.Failed, err.Error()
	}
	actionlog.Write(rec)
	if err != nil {
		return store.MailboxSuspension{}, err
	}
	return store.MailboxSuspension{Kind: store.SuspensionKindMailbox, Ref: acct.ID, Applied: []string{store.AppliedDisableSignIn}}, nil
}

// release enables sign-in on the account CSM suspended, found by its id: the
// address may name another account by now.
func (b stalwartMailBackend) release(rec store.MailboxSuspension, actor string) error {
	client, err := stalwartClient(b.cfg())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), stalwartCallTimeout)
	defer cancel()
	err = client.EnableSignIn(ctx, rec.Ref)
	entry := actionlog.Record{
		Op:          "operate.release_mailbox",
		Action:      "enable_signin",
		Actor:       actionlog.WebUI,
		ActorDetail: actor,
		Target:      rec.Subject,
		Account:     rec.Ref,
		Result:      actionlog.Applied,
	}
	if err != nil {
		entry.Result, entry.Error = actionlog.Failed, err.Error()
	}
	actionlog.Write(entry)
	return err
}

// active reads each account's sign-in state. A deleted account is no longer
// suspended; one that cannot be read is left out of the map.
func (b stalwartMailBackend) active(recs []store.MailboxSuspension) (map[string]bool, error) {
	client, err := stalwartClient(b.cfg())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), stalwartCallTimeout)
	defer cancel()
	live := make(map[string]bool, len(recs))
	var errs []error
	for _, r := range recs {
		acct, found, err := client.Account(ctx, r.Ref)
		if err != nil {
			errs = append(errs, fmt.Errorf("sign-in state of %s: %w", r.Subject, err))
			continue
		}
		live[r.ID] = found && acct.SignInDisabled
	}
	return live, errors.Join(errs...)
}
