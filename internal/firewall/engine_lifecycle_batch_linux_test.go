//go:build linux

package firewall

import (
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/pidginhost/csm/internal/actionlog"
)

type capturedAuditSink struct {
	single []actionlog.Record
	batch  [][]actionlog.Record
	fail   error
}

func (s *capturedAuditSink) Write(actionlog.Record) error { return nil }
func (s *capturedAuditSink) WriteDurable(r actionlog.Record) error {
	s.single = append(s.single, r)
	return s.fail
}
func (s *capturedAuditSink) WriteDurableBatch(rs []actionlog.Record) error {
	s.batch = append(s.batch, rs)
	return s.fail
}

func captureFirewallAudit(t *testing.T) *capturedAuditSink {
	t.Helper()
	sink := &capturedAuditSink{}
	actionlog.SetSink(sink, "")
	t.Cleanup(func() { actionlog.SetSink(nil, "") })
	return sink
}

// batchEvidence is an admitted two-member batch with the kernel evidence its
// planner records: both members' elements are added to an empty set.
func batchEvidence() FirewallAction {
	a := manifestBatch()
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	a.CreatedAt, a.UpdatedAt, a.Phase, a.AuditVersion = at, at.Add(time.Minute), "verified", 3
	for _, m := range a.Members {
		a.After.Blocked = append(a.After.Blocked, BlockedEntry{IP: m.Request.Target, Reason: m.Request.Reason, Source: "scan", BlockedAt: at, ExpiresAt: at.Add(m.Request.TTL), ActionID: m.Request.ID})
	}
	return withBatchKernelEvidence(a)
}

func withBatchKernelEvidence(a FirewallAction) FirewallAction {
	desired := desiredActionSets(a.After, true, a.CreatedAt)
	v6 := len(desired["blocked_ips6"]) > 0
	a.KernelBefore = []ActionSet{{Name: "blocked_ips", Exists: true}, {Name: "blocked_ips6", Exists: v6}}
	a.KernelAfter = []ActionSet{{Name: "blocked_ips", Exists: true, Elements: desired["blocked_ips"]}, {Name: "blocked_ips6", Exists: v6, Elements: desired["blocked_ips6"]}}
	return a
}

func TestFirewallAuditWritesOneRecordPerBatchMember(t *testing.T) {
	sink := captureFirewallAudit(t)
	a := batchEvidence()
	a.Members[1].Request.FindingID, a.Members[1].Request.IncidentID = "finding-two", "incident-two"
	if err := writeFirewallActionAudit(a); err != nil {
		t.Fatal(err)
	}
	if len(sink.single) != 0 || len(sink.batch) != 1 || len(sink.batch[0]) != 2 {
		t.Fatalf("batch audit = single %#v, batch %#v; want one durable write of both members", sink.single, sink.batch)
	}
	for i, r := range sink.batch[0] {
		m := a.Members[i].Request
		if r.ActionID != m.ID || r.ActionVersion != 3 || r.Target != m.Target || r.Reason != m.Reason || r.FindingID != m.FindingID || r.IncidentID != m.IncidentID {
			t.Errorf("member %d record = %#v", i, r)
		}
		if r.Op != "respond.block_ip" || r.Action != "block" || r.Result != actionlog.Result("verified") || !r.Timestamp.Equal(a.UpdatedAt) || r.Actor != actionlog.Actor("auto") {
			t.Errorf("member %d record = %#v, want the batch outcome", i, r)
		}
	}
}

func TestFirewallAuditKeepsOneRecordForOneRequest(t *testing.T) {
	sink := captureFirewallAudit(t)
	req := ActionRequest{ID: "request-one", Operation: "unblock", Target: "203.0.113.90", Actor: "cli", Source: "cli", Reason: "operator"}
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, a := range []FirewallAction{
		{Request: req, Phase: "failed", Detail: "not applied", AuditVersion: 2, UpdatedAt: at},
		{Request: req, Members: []ActionMember{{Request: req}}, Phase: "failed", Detail: "not applied", AuditVersion: 2, UpdatedAt: at},
	} {
		sink.single, sink.batch = nil, nil
		if err := writeFirewallActionAudit(a); err != nil {
			t.Fatal(err)
		}
		if len(sink.batch) != 0 || len(sink.single) != 1 {
			t.Fatalf("one-request audit = single %#v, batch %#v", sink.single, sink.batch)
		}
		r := sink.single[0]
		if r.ActionID != req.ID || r.ActionVersion != 2 || r.Target != req.Target || r.Op != "operate.manual_firewall" || r.Action != "unblock" || r.Result != actionlog.Result("failed") || r.Error != "not applied" {
			t.Fatalf("one-request record = %#v", r)
		}
	}
}

func TestFirewallBatchAuditFailureIsReported(t *testing.T) {
	sink := captureFirewallAudit(t)
	sink.fail = errors.New("audit sink unavailable")
	if err := writeFirewallActionAudit(batchEvidence()); !errors.Is(err, sink.fail) {
		t.Fatalf("batch audit failure = %v", err)
	}
}

func TestBatchEvidenceNamesEveryMember(t *testing.T) {
	validator := engineActionKernel{}
	if err := validator.ValidateEvidence(batchEvidence()); err != nil {
		t.Fatalf("complete batch evidence refused: %v", err)
	}
	expired := batchEvidence()
	expired.After.Blocked[0].BlockedAt = expired.CreatedAt.Add(-2 * time.Hour)
	expired.After.Blocked[0].ExpiresAt = expired.CreatedAt.Add(-time.Hour)
	if err := validator.ValidateEvidence(withBatchKernelEvidence(expired)); err == nil {
		t.Error("a member that expired before planning supplied valid evidence")
	}
	mixed := batchEvidence()
	mixed.Members[1].Request.Target, mixed.After.Blocked[1].IP = "2001:db8::11", "2001:db8::11"
	if err := validator.ValidateEvidence(withBatchKernelEvidence(mixed)); err != nil {
		t.Fatalf("an IPv4 and an IPv6 member refused: %v", err)
	}
	cases := map[string]func(*FirewallAction){
		"member without a row": func(a *FirewallAction) {
			a.After.Blocked = a.After.Blocked[:1]
			*a = withBatchKernelEvidence(*a)
		},
		"member row of another member": func(a *FirewallAction) {
			a.After.Blocked[1].ActionID = "member-one"
			*a = withBatchKernelEvidence(*a)
		},
		"member row for another address": func(a *FirewallAction) {
			a.After.Blocked[1].IP = "203.0.113.12"
			*a = withBatchKernelEvidence(*a)
		},
		"IPv6 member without its set": func(a *FirewallAction) {
			a.Members[1].Request.Target, a.After.Blocked[1].IP = "2001:db8::11", "2001:db8::11"
			*a = withBatchKernelEvidence(*a)
			a.KernelBefore[1], a.KernelAfter[1] = ActionSet{Name: "blocked_ips6"}, ActionSet{Name: "blocked_ips6"}
		},
		"member already held before": func(a *FirewallAction) {
			a.KernelBefore[0].Elements = []ActionElement{{Key: net.ParseIP(a.Members[1].Request.Target).To4(), Comment: "csm:earlier"}}
		},
		"member element not its row": func(a *FirewallAction) {
			a.After.Blocked[1].Reason = "other"
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			a := batchEvidence()
			change(&a)
			if err := validator.ValidateEvidence(a); err == nil {
				t.Fatal("incomplete batch evidence accepted")
			}
		})
	}
}

// A sink failure or lost acknowledgement can redeliver a whole batch. Each
// logical member event keeps its identity and payload across that retry.
type batchAuditRetryStore struct {
	ActionStore
	a       FirewallAction
	failAck bool
	acks    int
}

func (s *batchAuditRetryStore) FirewallAuditPending() ([]FirewallAction, error) {
	if s.a.AuditAck == s.a.AuditVersion {
		return nil, nil
	}
	return []FirewallAction{s.a}, nil
}
func (s *batchAuditRetryStore) AcknowledgeFirewallAudit(id string, version uint64) error {
	if id != s.a.Request.ID || version != s.a.AuditVersion {
		return errors.New("wrong batch audit acknowledgement")
	}
	s.acks++
	if s.failAck {
		s.failAck = false
		return errors.New("lost audit acknowledgement")
	}
	s.a.AuditAck = version
	return nil
}

func TestFirewallBatchAuditRetryKeepsMemberIdentity(t *testing.T) {
	for _, phase := range []string{"verified", "failed", "unknown"} {
		for _, lost := range []string{"sink", "ack"} {
			t.Run(phase+"/"+lost, func(t *testing.T) {
				sink := captureFirewallAudit(t)
				a := batchEvidence()
				a.Phase, a.Detail = phase, "recorded outcome"
				a.Members[1].Request.FindingID = "finding-two"
				a.Members[1].Request.IncidentID = "incident-two"
				s := &batchAuditRetryStore{a: a, failAck: lost == "ack"}
				if lost == "sink" {
					sink.fail = errors.New("lost durable delivery")
				}
				l := &Lifecycle{Store: s, Audit: writeFirewallActionAudit}
				if err := l.DeliverAudit(); err == nil || s.a.AuditAck != 0 {
					t.Fatalf("lost delivery acknowledged: %v, ack %d", err, s.a.AuditAck)
				}
				if lost == "sink" && s.acks != 0 {
					t.Fatal("failed sink was acknowledged")
				}
				sink.fail = nil
				if err := l.DeliverAudit(); err != nil {
					t.Fatal(err)
				}
				if len(sink.single) != 0 || len(sink.batch) != 2 || len(sink.batch[0]) != 2 || !reflect.DeepEqual(sink.batch[0], sink.batch[1]) {
					t.Fatalf("retry changed member records: single %#v, batch %#v", sink.single, sink.batch)
				}
				seen := map[string]bool{}
				for i, r := range sink.batch[1] {
					if r.ActionID != a.Members[i].Request.ID || seen[r.ActionID] || r.ActionVersion != a.AuditVersion || r.Result != actionlog.Result(phase) || r.Error != a.Detail || !r.Timestamp.Equal(a.UpdatedAt) {
						t.Fatalf("retry lost member identity or outcome: %#v", r)
					}
					seen[r.ActionID] = true
				}
				if err := l.DeliverAudit(); err != nil || len(sink.batch) != 2 || s.a.AuditAck != a.AuditVersion {
					t.Fatalf("acknowledged batch redelivered: %v, writes %d", err, len(sink.batch))
				}
			})
		}
	}
}

func TestBatchEvidenceAllowsDisabledFamilyInPriorState(t *testing.T) {
	a := batchEvidence()
	old := BlockedEntry{IP: "2001:db8::90", Reason: "earlier", BlockedAt: a.CreatedAt, ExpiresAt: a.CreatedAt.Add(time.Hour)}
	a.Before.Blocked = append(a.Before.Blocked, old)
	a.After.Blocked = append(a.After.Blocked, old)
	if err := (engineActionKernel{}).ValidateEvidence(a); err != nil {
		t.Fatalf("disabled legacy IPv6 row poisoned IPv4 batch: %v", err)
	}
}

func TestBatchEvidenceExpiredMembersRemainUnknown(t *testing.T) {
	for _, liveMember := range []bool{false, true} {
		for _, phase := range []string{"executing", "applied", "unknown"} {
			name := phase + "/absent"
			if liveMember {
				name = phase + "/partial"
			}
			t.Run(name, func(t *testing.T) {
				a := batchEvidence()
				a.Phase = phase
				a.After.Blocked[1].ExpiresAt = a.CreatedAt.Add(3 * time.Hour)
				a.Members[1].Request.TTL = 3 * time.Hour
				a = withBatchKernelEvidence(a)
				at := a.CreatedAt.Add(2 * time.Hour)
				var live []nftables.SetElement
				if liveMember {
					row := a.After.Blocked[1]
					live = []nftables.SetElement{{Key: net.ParseIP(row.IP).To4(), Comment: stateFingerprint(row), Timeout: time.Hour, Expires: time.Hour}}
				}
				e := newBlockedSetWireTestEngine(t, leaseActionReadConn(t, live))
				e.expiryClock = func() time.Time { return at }
				e.mu.Lock()
				observation, err := (engineActionKernel{e}).ObserveFirewallAction(a)
				e.mu.Unlock()
				if err != nil || observation.Before || observation.After {
					t.Fatalf("expired member supplied an outcome: %+v, %v", observation, err)
				}
			})
		}
	}
}

func TestBatchEvidenceIgnoresEarlierRowsWithReusedIDs(t *testing.T) {
	for _, sameTarget := range []bool{false, true} {
		for _, applied := range []bool{false, true} {
			name := "other_target"
			if sameTarget {
				name = "same_target"
			}
			if applied {
				name += "/after"
			} else {
				name += "/before"
			}
			t.Run(name, func(t *testing.T) {
				a := batchEvidence()
				memberRows := append([]BlockedEntry(nil), a.After.Blocked...)
				old := BlockedEntry{IP: "203.0.113.99", Reason: "earlier", ActionID: a.Members[0].Request.ID, BlockedAt: a.CreatedAt.Add(-time.Hour), ExpiresAt: a.CreatedAt.Add(500 * time.Millisecond)}
				if sameTarget {
					old.IP, old.ExpiresAt = a.Members[0].Request.Target, a.CreatedAt.Add(-time.Second)
				}
				a.Before.Blocked = append(a.Before.Blocked, old)
				a.After.Blocked = append([]BlockedEntry{old}, a.After.Blocked...)
				a = withBatchKernelEvidence(a)
				a.KernelBefore[0].Elements = desiredActionSets(a.Before, true, a.CreatedAt)["blocked_ips"]
				if err := (engineActionKernel{}).ValidateEvidence(a); err != nil {
					t.Fatalf("earlier row poisoned member evidence: %v", err)
				}
				at := a.CreatedAt.Add(time.Second)
				var live []nftables.SetElement
				if applied {
					for _, row := range memberRows {
						left := row.ExpiresAt.Sub(at)
						live = append(live, nftables.SetElement{Key: net.ParseIP(row.IP).To4(), Comment: stateFingerprint(row), Timeout: left, Expires: left})
					}
				}
				e := newBlockedSetWireTestEngine(t, leaseActionReadConn(t, live))
				e.expiryClock = func() time.Time { return at }
				e.mu.Lock()
				observation, err := (engineActionKernel{e}).ObserveFirewallAction(a)
				e.mu.Unlock()
				if err != nil || observation.Before != !applied || observation.After != applied {
					t.Fatalf("earlier row hid current member evidence: %+v, %v", observation, err)
				}
			})
		}
	}
}

func TestBatchEvidenceTimeoutRoundingCannotProveFailure(t *testing.T) {
	a := batchEvidence()
	at := a.CreatedAt.Add(time.Hour - 500*time.Microsecond)
	e := newBlockedSetWireTestEngine(t, leaseActionReadConn(t, nil))
	e.expiryClock = func() time.Time { return at }
	e.mu.Lock()
	observation, err := (engineActionKernel{e}).ObserveFirewallAction(a)
	e.mu.Unlock()
	if err != nil || observation.Before || observation.After {
		t.Fatalf("timeout rounding supplied an outcome: %+v, %v", observation, err)
	}
}

func TestBatchEvidenceUsesOneKernelTransaction(t *testing.T) {
	for _, reject := range []bool{false, true} {
		name := "success"
		if reject {
			name = "atomic rejection"
		}
		t.Run(name, func(t *testing.T) {
			attempts := 0
			conn, captured := capturingLifecycleConn(t, func(attempt int) bool { attempts = attempt; return reject && attempt == 1 })
			e := newBlockedSetWireTestEngine(t, conn)
			a := batchEvidence()
			e.expiryClock = func() time.Time { return a.CreatedAt }
			err := (engineActionKernel{e}).ApplyFirewallAction(a)
			if attempts != 1 || (reject && err == nil) || (!reject && err != nil) {
				t.Fatalf("batch transaction attempts %d, err %v, reject %t", attempts, err, reject)
			}
			if !reject {
				timeouts := newSetElemTimeouts(t, *captured, "blocked_ips")
				if len(timeouts) != 2 || timeouts[0] == nil || timeouts[1] == nil || *timeouts[0] != time.Hour || *timeouts[1] != time.Hour {
					t.Fatalf("batch did not encode both finite leases: %v", timeouts)
				}
			}
		})
	}
}

func TestBatchEvidenceRetainedRowOrder(t *testing.T) {
	for _, sameTarget := range []bool{false, true} {
		for _, oldLast := range []bool{false, true} {
			name := "other_target"
			if sameTarget {
				name = "same_target"
			}
			if oldLast {
				name += "/old_last"
			} else {
				name += "/old_first"
			}
			t.Run(name, func(t *testing.T) {
				a := batchEvidence()
				old := BlockedEntry{IP: "203.0.113.99", Reason: "earlier", ActionID: a.Members[0].Request.ID, BlockedAt: a.CreatedAt.Add(-time.Hour), ExpiresAt: a.CreatedAt.Add(500 * time.Millisecond)}
				if sameTarget {
					old.IP = a.Members[0].Request.Target
					old.ExpiresAt = a.CreatedAt.Add(-time.Second)
				}
				a.Before.Blocked = append(a.Before.Blocked, old)
				memberIndex := 0
				if oldLast {
					a.After.Blocked = append(a.After.Blocked, old)
				} else {
					a.After.Blocked = append([]BlockedEntry{old}, a.After.Blocked...)
					memberIndex = 1
				}
				a = withBatchKernelEvidence(a)
				a.KernelBefore[0].Elements = desiredActionSets(a.Before, true, a.CreatedAt)["blocked_ips"]
				if err := (engineActionKernel{}).ValidateEvidence(a); err != nil {
					t.Fatalf("retained row order hid the current member: %v", err)
				}
				a.After.Blocked[memberIndex].ActionID = "wrong-member"
				a = withBatchKernelEvidence(a)
				a.KernelBefore[0].Elements = desiredActionSets(a.Before, true, a.CreatedAt)["blocked_ips"]
				if err := (engineActionKernel{}).ValidateEvidence(a); err == nil {
					t.Fatal("retained row supplied the missing current member")
				}
			})
		}
	}
}

func TestBatchEvidenceExpiryBetweenApplyAndVerify(t *testing.T) {
	for _, left := range []time.Duration{0, 500 * time.Microsecond} {
		t.Run(left.String(), func(t *testing.T) {
			a := batchEvidence()
			a.Members[0].Request.TTL = time.Second
			a.After.Blocked[0].ExpiresAt = a.CreatedAt.Add(time.Second)
			a = withBatchKernelEvidence(a)
			a.Phase = "executing"
			now := a.After.Blocked[0].ExpiresAt.Add(-time.Millisecond)
			attempts := 0
			conn, captured := capturingLifecycleConn(t, func(attempt int) bool { attempts = attempt; return false })
			e := newBlockedSetWireTestEngine(t, conn)
			e.expiryClock = func() time.Time { return now }
			e.mu.Lock()
			defer e.mu.Unlock()
			kernel := engineActionKernel{e}
			if err := kernel.ApplyFirewallAction(a); err != nil {
				t.Fatal(err)
			}
			if timeouts := newSetElemTimeouts(t, *captured, "blocked_ips"); attempts != 1 || len(timeouts) != 2 || timeouts[0] == nil || *timeouts[0] != time.Millisecond {
				t.Fatalf("apply did not write both finite leases once: attempts %d, timeouts %v", attempts, timeouts)
			}
			a.Phase = "applied"
			now = a.After.Blocked[0].ExpiresAt.Add(-left)
			row := a.After.Blocked[1]
			remaining := row.ExpiresAt.Sub(now)
			e.conn = leaseActionReadConn(t, []nftables.SetElement{{Key: net.ParseIP(row.IP).To4(), Comment: stateFingerprint(row), Timeout: remaining, Expires: remaining}})
			observed, err := kernel.ObserveFirewallAction(a)
			if err != nil || observed.Before || observed.After {
				t.Fatalf("immediate verification proved an expired member: %+v, %v", observed, err)
			}
			a.Phase = "unknown"
			observed, err = kernel.ObserveFirewallAction(a)
			if err != nil || observed.Before || observed.After {
				t.Fatalf("recovery proved an expired member: %+v, %v", observed, err)
			}
		})
	}
}
