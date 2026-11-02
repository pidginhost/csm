package learnwatch

import (
	"context"
	"errors"
	"hash/fnv"
	"math"
	"strings"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/dovecot"
)

// Reporter ids of domains and mailboxes lie in [1<<32, 1<<62): above every
// 32-bit UID, so they never meet an account's or a domainless user's, and
// never 0 or -1, which the scheduler and the learner reserve.
const (
	minReporterID = 1 << 32
	reporterMask  = 1<<62 - 1
)

// Reporter ids need a 64-bit int, as every shipped target has; this
// constant does not compile where int is narrower.
const _ uint64 = math.MaxInt - reporterMask

// ReporterID is the learning reporter of a Postfix mailbox: its domain in
// domain mode, the mailbox itself in mailbox mode. Both are lower case, as
// Dovecot discovery and exempt matching give them. The id is a hash, so it
// survives restarts and watcher resets. A domainless user is not passed
// here: it votes under its own userdb uid.
func ReporterID(mode, domain, mailbox string) int {
	key := "d:" + domain
	if mode == antispam.ReporterMailbox {
		key = "m:" + mailbox
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	return int(minReporterID | h.Sum64()&reporterMask) // #nosec G115 -- below 1<<62; int is 64-bit, asserted above
}

// DovecotSource is the discovery a Postfix registry reads; dovecot.Dovecot
// is one.
type DovecotSource interface {
	Snapshot(context.Context) (dovecot.Snapshot, error)
	Users(context.Context) ([]string, error)
}

// Postfix is the reporter registry of a Postfix and Dovecot host. Each mail
// domain, or each mailbox in mailbox mode, is one reporter whose mailboxes
// bring their own Junk folders and file owners. Exempt mailboxes and
// domains are not watched, and no opt-in file is read.
type Postfix struct {
	Dovecot DovecotSource
	// Reporter is antispam.ReporterDomain or antispam.ReporterMailbox.
	Reporter string
	// Exempt holds lower-case mailboxes and domains, as antispam.exempt.
	Exempt []string
}

var (
	errIncomplete = errors.New("the Dovecot mailbox listing is incomplete")
	errNoUsers    = errors.New("the Dovecot user listing is empty")
	// errUnconfirmed: the recheck can neither confirm nor refute a removal.
	errUnconfirmed = errors.New("the removal of a reporter cannot be confirmed")
)

// registry reads one complete snapshot. Only a complete snapshot says who
// is gone; anything less is an error, so the pass reports, cancels and
// prunes nothing.
func (p *Postfix) registry(ctx context.Context) (registry, error) {
	snap, err := p.Dovecot.Snapshot(ctx)
	if err == nil && !snap.Complete {
		err = errIncomplete
	}
	if err != nil {
		return registry{}, err
	}
	reg := registry{held: map[int]bool{}, junk: map[int]map[FolderKey]int{}, complete: true}
	// known holds each domainless user's uid, its reporter, which the
	// recheck listing does not show; 0 for one refused as root.
	known := map[string]int{}
	// A skipped user is present, not removed: its reporter keeps its
	// reservations and its folders keep their state.
	skip := func(user, reason string) {
		reg.skips = append(reg.skips, reason)
		_, domain, found := strings.Cut(user, "@")
		switch {
		case user == "" || antispam.IsExempt(p.Exempt, user):
			// A refused name or an exempt mailbox is never watched.
		case found:
			id := ReporterID(p.Reporter, domain, user)
			reg.held[id] = true
			reg.unchecked = append(reg.unchecked, id)
		case reason == dovecot.SkipUIDRoot:
			known[user] = 0
		default:
			// Its reporter is a uid the skip does not carry.
			reg.complete = false
		}
	}
	for _, m := range snap.Mailboxes {
		switch {
		case antispam.IsExempt(p.Exempt, m.User):
			continue
		case m.UID <= 0:
			skip(m.User, dovecot.SkipUIDRoot)
			continue
		}
		id := m.UID
		if m.Domain != "" {
			id = ReporterID(p.Reporter, m.Domain, m.User)
		} else {
			known[m.User] = m.UID
		}
		if reg.junk[id] == nil {
			reg.junk[id] = map[FolderKey]int{}
			reg.accounts = append(reg.accounts, Account{UID: id})
		}
		reg.held[id] = true
		for _, path := range m.Junk {
			reg.junk[id][FolderKey{UID: id, Domain: m.Domain, Box: m.User, Folder: path}] = m.UID
		}
	}
	for _, s := range snap.Skips {
		skip(s.User, s.Reason)
	}
	reg.removed = func(ctx context.Context, uid int) (bool, error) { return p.removed(ctx, known, uid) }
	return reg, nil
}

// removed rechecks with a fresh identity-only listing that reporter uid is
// gone: a domain or mailbox listed again keeps it. A domainless user's
// reporter is its uid, which the listing does not show, so a domainless
// name the pass did not resolve leaves the removal of a uid unconfirmed.
func (p *Postfix) removed(ctx context.Context, known map[string]int, uid int) (bool, error) {
	users, err := p.Dovecot.Users(ctx)
	if err == nil && len(users) == 0 {
		err = errNoUsers
	}
	if err != nil {
		return false, err
	}
	for _, u := range users {
		_, domain, found := strings.Cut(u, "@")
		switch {
		case antispam.IsExempt(p.Exempt, u):
		case found:
			if ReporterID(p.Reporter, domain, u) == uid {
				return false, nil
			}
		case uid < minReporterID:
			if _, ok := known[u]; !ok {
				return false, errUnconfirmed
			}
		}
	}
	return true, nil
}
