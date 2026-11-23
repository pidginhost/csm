package checks

import (
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// DetachedWebProcessRespawnCheck reports a shell a web request left running
// that keeps coming back after CSM stops it: something in the account, most
// likely a PHP file requests keep running, starts it again.
const DetachedWebProcessRespawnCheck = "detached_web_process_respawn"

// detachedRespawnWindow is how long CSM remembers the detached shells it
// stopped for one owner, and how often it escalates the same owner.
const detachedRespawnWindow = 24 * time.Hour

// detachedRespawnMemory counts detached shells CSM stopped, per owner. It
// only adds findings: the kill never reads it, so a respawner cannot use it
// to switch the kill off.
type detachedRespawnMemory struct {
	mu     sync.Mutex
	now    func() time.Time
	owners map[string]*detachedRespawnOwner
}

type detachedRespawnOwner struct {
	stops     []time.Time
	escalated time.Time
}

func newDetachedRespawnMemory(now func() time.Time) *detachedRespawnMemory {
	return &detachedRespawnMemory{now: now, owners: make(map[string]*detachedRespawnOwner)}
}

var detachedRespawns = newDetachedRespawnMemory(time.Now)

// accountScanRequester queues a malware scan of a hosting account and returns
// the job ID. The daemon wires its scan job manager; nil means none.
var accountScanRequester atomic.Pointer[func(account string) (string, error)]

// SetAccountScanRequester wires the account scan queue a respawning detached
// shell uses. Passing nil clears it.
func SetAccountScanRequester(fn func(account string) (string, error)) {
	if fn == nil {
		accountScanRequester.Store(nil)
		return
	}
	accountScanRequester.Store(&fn)
}

// noteStop records that CSM stopped the detached shell of f, owned by uid,
// and returns the escalation due: from the second stop within the window,
// once per owner per window.
func (m *detachedRespawnMemory) noteStop(f alert.Finding, uid string) (alert.Finding, bool) {
	owner := f.TenantID
	if owner == "" {
		owner = "uid " + uid
	}
	m.mu.Lock()
	now := m.now()
	cutoff := now.Add(-detachedRespawnWindow)
	for key, o := range m.owners {
		o.stops = slices.DeleteFunc(o.stops, func(at time.Time) bool { return !at.After(cutoff) })
		if len(o.stops) == 0 && o.escalated.Before(cutoff) {
			delete(m.owners, key)
		}
	}
	o := m.owners[owner]
	if o == nil {
		o = &detachedRespawnOwner{}
		m.owners[owner] = o
	}
	o.stops = append(o.stops, now)
	stops := len(o.stops)
	if stops < 2 || o.escalated.After(cutoff) {
		m.mu.Unlock()
		return alert.Finding{}, false
	}
	o.escalated = now
	m.mu.Unlock()

	return alert.Finding{
		Severity: alert.Critical,
		Check:    DetachedWebProcessRespawnCheck,
		Message:  fmt.Sprintf("Shell left running by web requests keeps coming back for %s: stopped %d times in 24 hours", owner, stops),
		Details: "CSM stopped a shell a web request left running, and another one appeared. Something keeps starting it, most likely a PHP file that requests still run; the PHP handler socket below names the site.\n" +
			respawnScan(f.TenantID) + "\nLatest occurrence:\n" + f.Details,
		TenantID:  f.TenantID,
		Timestamp: now,
	}, true
}

// respawnScan queues a malware scan of the account and says what happened.
func respawnScan(account string) string {
	if account == "" {
		return "No malware scan was queued: the process owner is not a hosting account."
	}
	fn := accountScanRequester.Load()
	if fn == nil {
		return "No malware scan was queued: the scan queue is not available."
	}
	id, err := (*fn)(account)
	if err != nil {
		return fmt.Sprintf("No malware scan was queued: %v.", err)
	}
	return fmt.Sprintf("A malware scan of the account was queued as job %s.", id)
}
