package daemon

import (
	"net/netip"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/ipmap"
	"github.com/pidginhost/csm/internal/mailstats"
	"github.com/pidginhost/csm/internal/stalwartlog"
)

const (
	// stalwartVerdictHold is how long a queued message waits for its
	// delivery lines, from when CSM read it, so a backlog read in a burst
	// still joins.
	stalwartVerdictHold = 2 * time.Minute
	// stalwartVerdictMax bounds the messages held.
	stalwartVerdictMax = 8192
	// stalwartVerdictTick is how often held messages are booked while the
	// log is quiet.
	stalwartVerdictTick = 30 * time.Second
)

// stalwartVerdict is what Stalwart's spam filter did with one message.
type stalwartVerdict struct {
	ip   netip.Addr
	at   time.Time
	junk bool
}

// stalwartVerdicts joins a queued message, which names the sending address,
// to its delivery lines, which say whether the filter filed it to Junk.
// Both carry Stalwart's queue id and nothing else in common.
type stalwartVerdicts struct {
	mu    sync.Mutex
	m     map[string]*stalwartHeld
	order []*stalwartHeld // arrival order, so the oldest are at the front
}

type stalwartHeld struct {
	id       string
	read     time.Time
	ingested bool
	v        stalwartVerdict
}

func newStalwartVerdicts() *stalwartVerdicts {
	return &stalwartVerdicts{m: map[string]*stalwartHeld{}}
}

// queued holds the message id from ip, logged at at and read at now. It
// reports false only when the memory is full; a held id keeps its first
// entry.
func (v *stalwartVerdicts) queued(id string, ip netip.Addr, at, now time.Time) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.m[id]; ok {
		return true
	}
	if len(v.m) >= stalwartVerdictMax {
		return false
	}
	h := &stalwartHeld{id: id, read: now, v: stalwartVerdict{ip: ip, at: at}}
	v.m[id] = h
	v.order = append(v.order, h)
	return true
}

// ingested notes one delivery of message id. Junk for one recipient is Junk
// for the message.
func (v *stalwartVerdicts) ingested(id string, junk bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if h, ok := v.m[id]; ok {
		h.ingested = true
		h.v.junk = h.v.junk || junk
	}
}

// due forgets every message read at least stalwartVerdictHold before now
// and returns those that were delivered.
func (v *stalwartVerdicts) due(now time.Time) []stalwartVerdict {
	v.mu.Lock()
	defer v.mu.Unlock()
	n := 0
	for n < len(v.order) && now.Sub(v.order[n].read) >= stalwartVerdictHold {
		n++
	}
	return v.popLocked(n)
}

// drain forgets every message and returns those that were delivered.
func (v *stalwartVerdicts) drain() []stalwartVerdict {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.popLocked(len(v.order))
}

func (v *stalwartVerdicts) popLocked(n int) []stalwartVerdict {
	var out []stalwartVerdict
	for _, h := range v.order[:n] {
		delete(v.m, h.id)
		if h.ingested {
			out = append(out, h.v)
		}
	}
	clear(v.order[:n])
	v.order = v.order[n:]
	return out
}

// stalwartQueued holds an unauthenticated message until its delivery lines
// say what the filter did with it.
func (d *Daemon) stalwartQueued(ev stalwartlog.Event, s stalwartlog.Session) {
	st := d.stalwart
	id := ev.Fields["queueId"]
	// An HTTP listener can log an address from a forwarded header.
	if id == "" || st.ports.Of(s.LocalPort) == stalwartlog.ProtoHTTP {
		return
	}
	if !st.verdicts.queued(id, s.RemoteIP, ev.Time, time.Now()) {
		d.mailStats.RecordFilterVerdict(ev.Time, mailstats.FilterUnmatched)
	}
}

// stalwartClassify books a message the filter rejected or discarded. Stalwart
// logs no queued or delivery line for it, so the line's own session names
// the sender.
func (d *Daemon) stalwartClassify(ev stalwartlog.Event, s stalwartlog.Session, cfg *config.Config) {
	if d.stalwart.ports.Of(s.LocalPort) == stalwartlog.ProtoHTTP {
		return
	}
	var outcome string
	switch ev.Fields["result"] {
	case "reject":
		outcome = mailstats.FilterRejected
	case "discard":
		outcome = mailstats.FilterDiscarded
	default:
		return
	}
	d.mailStats.RecordFilterVerdict(ev.Time, outcome)
	d.recordStalwartVerdict(s.RemoteIP, true, ev.Time, cfg)
}

// sweepStalwartVerdicts books the messages whose hold has ended.
func (d *Daemon) sweepStalwartVerdicts(now time.Time, cfg *config.Config) {
	d.bookStalwartVerdicts(d.stalwart.verdicts.due(now), cfg)
}

// drainStalwartVerdicts books every delivered message without waiting, at
// shutdown.
func (d *Daemon) drainStalwartVerdicts(cfg *config.Config) {
	d.bookStalwartVerdicts(d.stalwart.verdicts.drain(), cfg)
}

func (d *Daemon) bookStalwartVerdicts(vs []stalwartVerdict, cfg *config.Config) {
	for _, v := range vs {
		outcome := mailstats.FilterDelivered
		if v.junk {
			outcome = mailstats.FilterJunk
		}
		d.mailStats.RecordFilterVerdict(v.at, outcome)
		d.recordStalwartVerdict(v.ip, v.junk, v.at, cfg)
	}
}

// recordStalwartVerdict records Stalwart's verdict about a sending address
// as spam evidence. Stalwart filters on its own, so this does not depend on
// CSM's antispam settings.
func (d *Daemon) recordStalwartVerdict(ip netip.Addr, spam bool, at time.Time, cfg *config.Config) {
	adb := attackdb.Global()
	if adb == nil || !ipmap.Recordable(ip, nil) || d.spamSenderExcluded(ip, cfg) {
		return
	}
	adb.RecordMailVerdict(ip.String(), spam, at)
}
