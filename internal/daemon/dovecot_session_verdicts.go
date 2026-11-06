package daemon

import (
	"container/list"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	// dovecotSessionVerdictTTL bounds the gap between a session's last
	// verdict and its login summary, by log time.
	dovecotSessionVerdictTTL = 5 * time.Minute
	// maxDovecotSessionVerdicts caps the sessions held. Losing a verdict only
	// withholds evidence, so a flood costs its attacker that and no more.
	maxDovecotSessionVerdicts = 4096
	// maxDovecotSessionNames caps the names one session keeps verdicts for.
	maxDovecotSessionNames = 4
)

type dovecotSessionName struct {
	name  string
	exist mailboxExistence
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

// Note keeps one verdict. A verdict that names no mailbox or cannot tell
// whether it exists adds nothing, so a flood of them costs nothing. Callers
// filter infra, private and loopback addresses first.
func (v *dovecotSessionVerdicts) Note(session, ip, account string, exist mailboxExistence, at time.Time) {
	name := normalizeSprayMailbox(account)
	if name == "" || exist == mailboxExistenceUnknown {
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
	s.at = at
	v.order.MoveToBack(elem)
	s.note(name, exist)
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
	s.at, s.spoiled, s.names = at, true, nil
	v.order.MoveToBack(elem)
}

// Take claims the session and returns what its verdicts said about account:
// Unknown when none named it, when ip is not the client that got them, or
// when they expired.
func (v *dovecotSessionVerdicts) Take(session, ip, account string, at time.Time) mailboxExistence {
	v.mu.Lock()
	defer v.mu.Unlock()
	elem, tracked := v.sessions[session]
	if !tracked {
		return mailboxExistenceUnknown
	}
	s := v.remove(elem)
	if s.ip != ip || at.Sub(s.at) > dovecotSessionVerdictTTL {
		return mailboxExistenceUnknown
	}
	name := normalizeSprayMailbox(account)
	for _, n := range s.names {
		if n.name == name {
			return n.exist
		}
	}
	return mailboxExistenceUnknown
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

func (s *dovecotSession) note(name string, exist mailboxExistence) {
	for i := range s.names {
		if s.names[i].name == name {
			s.names[i].exist = combineMailboxExistence(s.names[i].exist, exist)
			return
		}
	}
	// The login summary names the last attempt, so the oldest name goes.
	if len(s.names) >= maxDovecotSessionNames {
		s.names = slices.Delete(s.names, 0, 1)
	}
	s.names = append(s.names, dovecotSessionName{name: strings.Clone(name), exist: exist})
}

// dovecotLoginSession reads the session id of a login summary. user= comes
// first and is client text, so only the last session field is Dovecot's.
func dovecotLoginSession(line string) string {
	idx := strings.LastIndex(line, "session=<")
	if idx < 0 {
		return ""
	}
	return extractAngleBracket(line[idx:], "session=")
}
