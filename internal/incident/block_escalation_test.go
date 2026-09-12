package incident

import (
	"strconv"
	"testing"
	"time"
)

// escalationCorrelator wires a spray correlator whose clock the test drives.
func escalationCorrelator(t *testing.T, cap *blockCapture) (*Correlator, func(time.Time)) {
	t.Helper()
	cfg := sprayTestConfig(true, false)
	cfg.BlockAtSeverity = "high"
	cfg.BlockExpiry = 24 * time.Hour
	now := time.Unix(1_700_000_000, 0)
	c := NewCorrelator(CorrelatorConfig{
		SpraySuppression: cfg,
		OnSprayBlock:     cap.record,
	})
	c.openThreshold = 1
	c.now = func() time.Time { return now }
	if c.spray != nil {
		c.spray.now = c.now
	}
	return c, func(at time.Time) { now = at }
}

func sprayBurst(c *Correlator, at time.Time, from int) {
	for i := 0; i < 3; i++ {
		mb := "user" + strconv.Itoa(from+i) + "@example.com"
		_, _, _ = c.OnFinding(sprayFinding(mb, "192.0.2.10", at.Add(time.Duration(i)*time.Second)))
	}
}

// The block CSM applies expires, but the marker saying "already blocked" did
// not, so an attack that outlasted the expiry was never blocked again. On a
// production host one IP kept spraying for six days after its 24h block
// lapsed, with the incident open the whole time.
func TestSprayBlockReRequestedAfterTheBlockLapses(t *testing.T) {
	var cap blockCapture
	c, setNow := escalationCorrelator(t, &cap)
	start := time.Unix(1_700_000_000, 0)

	sprayBurst(c, start, 0)
	if got := cap.len(); got != 1 {
		t.Fatalf("blocks requested at open = %d, want 1", got)
	}

	// Still inside the first block: no second request.
	setNow(start.Add(12 * time.Hour))
	sprayBurst(c, start.Add(12*time.Hour), 10)
	if got := cap.len(); got != 1 {
		t.Fatalf("blocks requested while still blocked = %d, want 1", got)
	}

	// Past the expiry, with the attack continuing.
	setNow(start.Add(25 * time.Hour))
	sprayBurst(c, start.Add(25*time.Hour), 20)
	if got := cap.len(); got != 2 {
		t.Fatalf("blocks requested after the block lapsed = %d, want 2", got)
	}
}

// Each re-block lasts longer than the last, ending permanent.
func TestSprayBlockEscalatesThenGoesPermanent(t *testing.T) {
	var cap blockCapture
	c, setNow := escalationCorrelator(t, &cap)
	start := time.Unix(1_700_000_000, 0)

	sprayBurst(c, start, 0)
	at := start
	for _, step := range []time.Duration{25 * time.Hour, 8 * 24 * time.Hour} {
		at = at.Add(step)
		setNow(at)
		sprayBurst(c, at, int(step.Hours()))
	}
	if got := cap.len(); got != 3 {
		t.Fatalf("blocks requested = %d, want 3", got)
	}
	want := []time.Duration{24 * time.Hour, 7 * 24 * time.Hour, 0}
	for i, w := range want {
		if got := cap.calls[i].TTL; got != w {
			t.Errorf("block %d TTL = %v, want %v", i+1, got, w)
		}
	}

	// The third block is permanent, so nothing re-requests it however long
	// the attack runs.
	at = at.Add(365 * 24 * time.Hour)
	setNow(at)
	sprayBurst(c, at, 999)
	if got := cap.len(); got != 3 {
		t.Fatalf("blocks requested after a permanent block = %d, want 3", got)
	}
}

// Closing an incident ends the episode. A later recurrence is new activity and
// starts at the bottom of the ladder rather than jumping straight to a
// permanent block off the back of a months-old incident.
func TestResolvingAnIncidentResetsTheEscalationLadder(t *testing.T) {
	var cap blockCapture
	c, setNow := escalationCorrelator(t, &cap)
	start := time.Unix(1_700_000_000, 0)

	sprayBurst(c, start, 0)
	at := start.Add(25 * time.Hour)
	setNow(at)
	sprayBurst(c, at, 10)
	if got := cap.len(); got != 2 {
		t.Fatalf("blocks before resolving = %d, want 2", got)
	}

	var id string
	for _, inc := range c.Snapshot() {
		if inc.Kind == KindCredentialSpray {
			id = inc.ID
		}
	}
	if id == "" {
		t.Fatal("no credential_spray incident to resolve")
	}
	if err := c.SetStatus(id, StatusResolved, "operator closed"); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	for _, inc := range c.Snapshot() {
		if inc.ID == id && inc.AutoBlock.Count != 0 {
			t.Fatalf("resolved incident kept escalation state %+v", inc.AutoBlock)
		}
	}
}

// An operator blocking from the incident view must show up on the incident and
// must settle the automatic ladder: the hand-off has no business re-requesting
// a block for an address the operator just blocked.
func TestOperatorBlockRecordsAnActionAndSettlesTheLadder(t *testing.T) {
	var cap blockCapture
	c, setNow := escalationCorrelator(t, &cap)
	start := time.Unix(1_700_000_000, 0)
	sprayBurst(c, start, 0)

	var id string
	for _, inc := range c.Snapshot() {
		if inc.Kind == KindCredentialSpray {
			id = inc.ID
		}
	}
	if id == "" {
		t.Fatal("no credential_spray incident")
	}

	// A permanent operator block.
	if err := c.RecordOperatorBlock(id, "192.0.2.10", 0); err != nil {
		t.Fatalf("RecordOperatorBlock: %v", err)
	}
	inc, ok := c.Get(id)
	if !ok {
		t.Fatal("incident vanished")
	}
	if !hasIncidentAction(inc.Actions, "operator_block") {
		t.Error("incident missing operator_block action")
	}
	if inc.AutoBlock.Count == 0 || !inc.AutoBlock.ExpiresAt.IsZero() {
		t.Errorf("operator block left ladder state %+v, want a permanent entry", inc.AutoBlock)
	}

	before := cap.len()
	at := start.Add(400 * 24 * time.Hour)
	setNow(at)
	sprayBurst(c, at, 50)
	if got := cap.len(); got != before {
		t.Errorf("auto hand-off re-requested %d block(s) after an operator permanent block", got-before)
	}
}

func TestRecordOperatorBlockRejectsUnknownIncident(t *testing.T) {
	var cap blockCapture
	c, _ := escalationCorrelator(t, &cap)
	if err := c.RecordOperatorBlock("inc_missing", "192.0.2.10", time.Hour); err == nil {
		t.Fatal("RecordOperatorBlock accepted an unknown incident")
	}
}
