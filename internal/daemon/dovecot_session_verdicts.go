package daemon

import (
	"container/list"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/checks"
)

const (
	// dovecotSessionVerdictTTL bounds the gap between a session's last
	// verdict and its login summary, by log time.
	dovecotSessionVerdictTTL = 5 * time.Minute
	// maxDovecotSessionVerdicts caps the sessions held. Eviction loses what a
	// session held, so a flood mostly withholds evidence. A lost answer can
	// matter only if the flood lands between two answers to one request.
	maxDovecotSessionVerdicts = 4096
	// maxDovecotSessionNames caps the names one session keeps verdicts for.
	maxDovecotSessionNames = 4
)

type dovecotSessionName struct {
	name  string
	exist mailboxExistence
	at    time.Time
}

type dovecotSession struct {
	id      string
	ip      string
	at      time.Time
	spoiled bool
	names   []dovecotSessionName
}

// dovecotSessionVerdicts keeps what Dovecot's passdb verdicts said about the
// names tried in a login session until the session's login summary claims
// them. One verdict is one database's answer, so it stays here and reaches no
// tracker on its own. A session no summary claims stays until the cap evicts
// it. mu is a leaf: nothing here calls a tracker.
type dovecotSessionVerdicts struct {
	mu       sync.Mutex
	sessions map[string]*list.Element
	// order holds one *dovecotSession per entry, least recently noted first,
	// so eviction at the cap needs no scan.
	order *list.List
}

func newDovecotSessionVerdicts() *dovecotSessionVerdicts {
	return &dovecotSessionVerdicts{sessions: make(map[string]*list.Element), order: list.New()}
}

// Note keeps one verdict. A verdict that names no mailbox can pair with no
// login summary and adds nothing, so a flood of them costs nothing. Callers
// filter infra, private and loopback addresses first.
func (v *dovecotSessionVerdicts) Note(session, ip, account string, exist mailboxExistence, at time.Time) {
	name := normalizeSprayMailbox(account)
	if name == "" {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	elem := v.sessions[session]
	if elem != nil && at.Sub(elem.Value.(*dovecotSession).at) > dovecotSessionVerdictTTL {
		v.remove(elem)
		elem = nil
	}
	if elem == nil {
		elem = v.add(session, ip)
	}
	s := elem.Value.(*dovecotSession)
	// A session belongs to one client, and a spoiled one stays spoiled.
	if s.spoiled || s.ip != ip {
		return
	}
	if at.After(s.at) {
		s.at = at
	}
	v.order.MoveToBack(elem)
	s.note(name, exist, at)
}

// Spoil withholds a session whose request hit an auth error: a later database
// failed, so a rejection before or after it is not the request's answer. The
// tombstone stands in for the session under the same cap and TTL, so a later
// verdict cannot restore it. Client text can name other sessions here, which
// only withholds their verdicts.
func (v *dovecotSessionVerdicts) Spoil(session string, at time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	elem := v.sessions[session]
	if elem == nil {
		elem = v.add(session, "")
	}
	s := elem.Value.(*dovecotSession)
	if at.After(s.at) {
		s.at = at
	}
	s.spoiled, s.names = true, nil
	v.order.MoveToBack(elem)
}

// Take claims the session and returns what its verdicts said about account:
// Unknown when none named it, when ip is not the client that got them, or
// when they expired or were spoiled. withheld reports a session spoiled within
// the TTL, as opposed to an absent verdict: a mailbox lookup must not undo an
// auth-error veto.
func (v *dovecotSessionVerdicts) Take(session, ip, account string, at time.Time) (exist mailboxExistence, withheld bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	elem, tracked := v.sessions[session]
	if !tracked {
		return mailboxExistenceUnknown, false
	}
	s := v.remove(elem)
	if s.spoiled && at.Sub(s.at) <= dovecotSessionVerdictTTL {
		return mailboxExistenceUnknown, true
	}
	if s.ip != ip || at.Before(s.at) || at.Sub(s.at) > dovecotSessionVerdictTTL {
		return mailboxExistenceUnknown, false
	}
	name := normalizeSprayMailbox(account)
	for _, n := range s.names {
		if n.name == name && !at.Before(n.at) && at.Sub(n.at) <= dovecotSessionVerdictTTL {
			return n.exist, false
		}
	}
	return mailboxExistenceUnknown, false
}

// add starts an entry, evicting the least recently noted at the cap. Caller
// holds v.mu.
func (v *dovecotSessionVerdicts) add(session, ip string) *list.Element {
	if v.order.Len() >= maxDovecotSessionVerdicts {
		v.remove(v.order.Front())
	}
	session = strings.Clone(session)
	elem := v.order.PushBack(&dovecotSession{id: session, ip: ip})
	v.sessions[session] = elem
	return elem
}

// remove drops one session. Caller holds v.mu.
func (v *dovecotSessionVerdicts) remove(elem *list.Element) *dovecotSession {
	s := v.order.Remove(elem).(*dovecotSession)
	delete(v.sessions, s.id)
	return s
}

func (s *dovecotSession) note(name string, exist mailboxExistence, at time.Time) {
	for i := range s.names {
		if s.names[i].name == name {
			n := s.names[i]
			if at.Sub(n.at) <= dovecotSessionVerdictTTL {
				exist = combineMailboxExistence(n.exist, exist)
			}
			if n.at.After(at) {
				at = n.at
			}
			s.names[i] = dovecotSessionName{name: n.name, exist: exist, at: at}
			return
		}
	}
	// The login summary names the last attempt, so the oldest name goes.
	if len(s.names) >= maxDovecotSessionNames {
		if s.names[0].exist != mailboxMissing {
			s.spoiled, s.names = true, nil
			return
		}
		s.names = slices.Delete(s.names, 0, 1)
	}
	s.names = append(s.names, dovecotSessionName{name: strings.Clone(name), exist: exist, at: at})
}

// dovecotLoginSession reads the session id of a login summary. user= comes
// first and is client text. A session must be a complete field after the
// server's address fields, not a substring of the user or another field.
func dovecotLoginSession(line string) string {
	_, fields := checks.DovecotLoginFields(line)
	idx := strings.LastIndex(fields, ", session=<")
	if idx < 0 || checks.DovecotRemoteIP(fields[:idx]) == "" {
		return ""
	}
	field, _, _ := strings.Cut(fields[idx+len(", session="):], ", ")
	session, ok := dovecotSessionField(field)
	if !ok {
		return ""
	}
	return session
}
