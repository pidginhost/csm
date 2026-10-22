//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/nftables"
)

var errBatchPlanStop = errors.New("stop after capturing the batch plan")

// batchPlanStore answers planning reads from one committed state and
// captures every new plan instead of admitting it, so no kernel write runs.
type batchPlanStore struct {
	ActionStore
	state    FirewallState
	stored   map[string]FirewallAction
	admitted []FirewallAction
}

func (s *batchPlanStore) ReadFirewallState() (FirewallState, uint64, error) { return s.state, 7, nil }
func (s *batchPlanStore) PendingFirewallActions() ([]FirewallAction, error) { return nil, nil }
func (s *batchPlanStore) FirewallAuditPending() ([]FirewallAction, error)   { return nil, nil }
func (s *batchPlanStore) ReadFirewallAction(id string) (FirewallAction, error) {
	if a, ok := s.stored[id]; ok {
		return a, nil
	}
	return FirewallAction{}, ErrActionMissing
}
func (s *batchPlanStore) AdmitFirewallAction(a FirewallAction) (FirewallAction, bool, error) {
	if stored, ok := s.stored[a.Request.ID]; ok {
		return stored, false, nil
	}
	s.admitted = append(s.admitted, a)
	return FirewallAction{}, false, errBatchPlanStop
}

// batchPlanEngine plans against committed state whose timed rows the
// read-only kernel fixture already holds.
func batchPlanEngine(t *testing.T, cfg FirewallConfig, state FirewallState) (*Engine, *batchPlanStore) {
	t.Helper()
	at := time.Now().Round(0)
	var live []nftables.SetElement
	for _, elem := range desiredActionSets(state, false, at)["blocked_ips"] {
		var left time.Duration
		if !elem.ExpiresAt.IsZero() {
			left = elem.ExpiresAt.Sub(at)
		}
		live = append(live, nftables.SetElement{Key: elem.Key, Comment: elem.Comment, Timeout: left, Expires: left})
	}
	e := newBlockedSetWireTestEngine(t, leaseActionReadConn(t, live))
	e.cfg = &cfg
	e.expiryClock = func() time.Time { return at }
	s := &batchPlanStore{state: state, stored: map[string]FirewallAction{}}
	if err := e.AttachLifecycle(&Lifecycle{Store: s, Audit: func(FirewallAction) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	return e, s
}

func batchHeader() ActionRequest {
	return ActionRequest{ID: "batch-one", Operation: "block", Actor: "auto", Source: "scan", Automatic: true}
}

func batchMember(id, target string) ActionRequest {
	return ActionRequest{ID: id, Operation: "block", Target: target, Reason: "brute force", Actor: "auto", Source: "scan", Automatic: true, TTL: time.Hour, FindingID: "finding-" + id}
}

func TestBlockBatchPlansValidMembersTogether(t *testing.T) {
	committed := FirewallState{Allowed: []AllowedEntry{{IP: "198.51.100.7", Reason: "operator"}}}
	e, s := batchPlanEngine(t, FirewallConfig{InfraIPs: []string{"192.0.2.250"}}, committed)
	e.SetSoftAllowChecker(func(ip string) bool { return ip == "198.51.100.8" })
	shortTTL := batchMember("member-short", "203.0.113.30")
	shortTTL.TTL = 500 * time.Microsecond
	manual := batchMember("member-manual", "203.0.113.31")
	manual.Automatic = false
	otherSource := batchMember("member-source", "203.0.113.32")
	otherSource.Source = "manual"
	badReason := batchMember("member-reason", "203.0.113.34")
	badReason.Reason = "line\nbreak"
	noTTL := batchMember("member-ttl", "203.0.113.35")
	noTTL.TTL = 0
	undo := batchMember("member-undo", "203.0.113.36")
	undo.UndoOf = "earlier"
	detail := batchMember("member-detail", "203.0.113.37")
	detail.ActorDetail = "other"
	badLink := batchMember("member-link", "203.0.113.38")
	badLink.FindingID = "bad\xff"
	wrongOperation := batchMember("member-unblock", "203.0.113.39")
	wrongOperation.Operation = "unblock"
	members := []ActionRequest{
		batchMember("member-bad", "not-an-ip"),
		batchMember("member-a", "203.0.113.20"),
		batchMember("member-infra", "192.0.2.250"),
		batchMember("member-b", "::ffff:203.0.113.21"),
		batchMember("member-again", "203.0.113.20"),
		batchMember("member-a", "203.0.113.22"),
		batchMember("member-v6", "2001:db8::20"),
		batchMember("member-allowed", "198.51.100.7"),
		batchMember("member-verified", "198.51.100.8"),
		shortTTL, manual, otherSource,
		batchMember("batch-one", "203.0.113.33"),
		batchMember("member bad", "203.0.113.39"),
		badReason, noTTL, undo, detail, badLink, wrongOperation,
	}
	budget := &ScanAdmission{Window: "2026-01-02T03", Limit: 10}
	result, err := e.BlockBatchRequest(batchHeader(), members, budget)
	if !errors.Is(err, errBatchPlanStop) {
		t.Fatalf("batch = %v, want the captured plan", err)
	}
	want := []BlockRefusal{BlockRefusedInvalid, "", BlockRefusedProtected, "", BlockRefusedDuplicate, BlockRefusedDuplicate, BlockRefusedUnsupported, BlockRefusedAllowed, BlockRefusedAllowed, BlockRefusedExpired, BlockRefusedInvalid, BlockRefusedInvalid, BlockRefusedDuplicate,
		BlockRefusedInvalid, BlockRefusedInvalid, BlockRefusedInvalid, BlockRefusedInvalid, BlockRefusedInvalid, BlockRefusedInvalid, BlockRefusedInvalid}
	if fmt.Sprint(result.Refusals) != fmt.Sprint(want) {
		t.Fatalf("refusals = %q, want %q", result.Refusals, want)
	}
	if len(s.admitted) != 1 {
		t.Fatalf("admitted %d plans", len(s.admitted))
	}
	plan := s.admitted[0]
	if plan.Request != batchHeader() || plan.Budget != nil || plan.Revision != 7 || len(plan.Members) != 2 {
		t.Fatalf("plan header = %#v, budget %v, revision %d, members %d", plan.Request, plan.Budget, plan.Revision, len(plan.Members))
	}
	for i, target := range []string{"203.0.113.20", "203.0.113.21"} {
		m := plan.Members[i]
		if m.Request.ID != []string{"member-a", "member-b"}[i] || m.Request.Target != target || m.Request.Operation != "block" || m.Budget == nil || *m.Budget != *budget || m.Victims != nil {
			t.Errorf("member %d = %#v", i, m)
		}
	}
	if len(plan.After.Blocked) != 2 || len(plan.Before.Blocked) != 0 || len(plan.After.Allowed) != 1 {
		t.Fatalf("plan states = before %#v, after %#v", plan.Before, plan.After)
	}
	for i, row := range plan.After.Blocked {
		m := plan.Members[i].Request
		if row.IP != m.Target || row.ActionID != m.ID || row.Reason != m.Reason || row.Unverified || !row.ExpiresAt.Equal(row.BlockedAt.Add(m.TTL)) || !row.BlockedAt.Equal(plan.After.Blocked[0].BlockedAt) {
			t.Errorf("row %d = %#v", i, row)
		}
	}
	if len(plan.KernelBefore) == 0 || plan.KernelBefore[0].Name != "blocked_ips" {
		t.Fatalf("plan kernel evidence = %#v", plan.KernelBefore)
	}
}

// A member that expires before verification reads it back leaves the batch
// unknown, and an unknown batch holds every durable mutation until an
// operator resolves it. Such a member is refused at planning.
func TestBlockBatchRefusesMembersTooShortToVerify(t *testing.T) {
	e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
	short := batchMember("member-short", "203.0.113.47")
	short.TTL = blockBatchMinLifetime - time.Millisecond
	enough := batchMember("member-enough", "203.0.113.48")
	enough.TTL = blockBatchMinLifetime
	result, err := e.BlockBatchRequest(batchHeader(), []ActionRequest{short, enough, batchMember("member-hour", "203.0.113.49")}, nil)
	if !errors.Is(err, errBatchPlanStop) || fmt.Sprint(result.Refusals) != fmt.Sprint([]BlockRefusal{BlockRefusedExpired, "", ""}) {
		t.Fatalf("short member = %q, %v", result.Refusals, err)
	}
	if plan := s.admitted[0]; len(plan.Members) != 2 || plan.Members[0].Request.ID != "member-enough" {
		t.Fatalf("plan members = %#v", plan.Members)
	}
}

func TestBlockBatchRefusesExistingAndFullMembers(t *testing.T) {
	at := time.Now().Round(0)
	committed := FirewallState{Blocked: []BlockedEntry{
		{IP: "203.0.113.40", Reason: "earlier", BlockedAt: at, ExpiresAt: at.Add(2 * time.Hour)},
		{IP: "203.0.113.41", Reason: "earlier", BlockedAt: at, ExpiresAt: at.Add(time.Minute)},
		{IP: "203.0.113.42", Reason: "expired", BlockedAt: at.Add(-2 * time.Hour), ExpiresAt: at.Add(-time.Hour)},
		{IP: "203.0.113.45", Reason: "unproven", BlockedAt: at, ExpiresAt: at.Add(2 * time.Hour), Unverified: true},
		{IP: "203.0.113.46", Reason: "permanent", BlockedAt: at},
		{IP: "::ffff:203.0.113.40", Reason: "expired alias", BlockedAt: at.Add(-2 * time.Hour), ExpiresAt: at.Add(-time.Hour)},
	}}
	e, s := batchPlanEngine(t, FirewallConfig{DenyTempIPLimit: 4}, committed)
	members := []ActionRequest{
		batchMember("member-covered", "203.0.113.40"),
		batchMember("member-shorter", "203.0.113.41"),
		batchMember("member-unproven", "203.0.113.45"),
		batchMember("member-permanent", "203.0.113.46"),
		batchMember("member-expired-row", "203.0.113.42"),
		batchMember("member-next", "203.0.113.43"),
		batchMember("member-full", "203.0.113.44"),
	}
	result, err := e.BlockBatchRequest(batchHeader(), members, nil)
	if !errors.Is(err, errBatchPlanStop) {
		t.Fatalf("batch = %v", err)
	}
	want := []BlockRefusal{BlockRefusedExisting, BlockRefusedPending, BlockRefusedPending, BlockRefusedExisting, "", "", BlockRefusedFull}
	if fmt.Sprint(result.Refusals) != fmt.Sprint(want) {
		t.Fatalf("refusals = %q, want %q", result.Refusals, want)
	}
	if plan := s.admitted[0]; len(plan.Members) != 2 || plan.Members[0].Budget != nil || len(plan.After.Blocked) != 8 {
		t.Fatalf("plan = members %#v, after %#v", plan.Members, plan.After.Blocked)
	}
}

func TestBlockBatchRunsALoneMemberAsOneRequest(t *testing.T) {
	e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
	budget := &ScanAdmission{Window: "2026-01-02T03", Limit: 10}
	result, err := e.BlockBatchRequest(batchHeader(), []ActionRequest{batchMember("member-bad", "not-an-ip"), batchMember("member-a", "203.0.113.20")}, budget)
	if !errors.Is(err, errBatchPlanStop) || fmt.Sprint(result.Refusals) != fmt.Sprint([]BlockRefusal{BlockRefusedInvalid, ""}) {
		t.Fatalf("lone member = %q, %v", result.Refusals, err)
	}
	plan := s.admitted[0]
	if plan.Request != batchMember("member-a", "203.0.113.20") || plan.Members != nil || plan.Budget != budget {
		t.Fatalf("lone member plan = %#v, members %#v, budget %v", plan.Request, plan.Members, plan.Budget)
	}
	if len(plan.After.Blocked) != 1 || plan.After.Blocked[0].ActionID != "" || plan.After.Blocked[0].IP != "203.0.113.20" {
		t.Fatalf("lone member row = %#v", plan.After.Blocked)
	}
}

func TestBlockBatchWithNoValidMemberAdmitsNothing(t *testing.T) {
	e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
	result, err := e.BlockBatchRequest(batchHeader(), []ActionRequest{batchMember("member-bad", "not-an-ip")}, nil)
	if err != nil || len(s.admitted) != 0 || fmt.Sprint(result.Refusals) != fmt.Sprint([]BlockRefusal{BlockRefusedInvalid}) || result.Action.Request.ID != "" {
		t.Fatalf("no valid member = %#v, %v, admitted %d", result, err, len(s.admitted))
	}
}

func TestBlockBatchRefusesInvalidCalls(t *testing.T) {
	two := []ActionRequest{batchMember("member-a", "203.0.113.20"), batchMember("member-b", "203.0.113.21")}
	tooMany := make([]ActionRequest, MaxActionMembers+1)
	for i := range tooMany {
		tooMany[i] = batchMember(fmt.Sprintf("member-%03d", i), fmt.Sprintf("198.51.100.%d", i))
	}
	headers := map[string]func(*ActionRequest){
		"target":         func(h *ActionRequest) { h.Target = "203.0.113.9" },
		"reason":         func(h *ActionRequest) { h.Reason = "batch" },
		"link":           func(h *ActionRequest) { h.FindingID = "finding" },
		"incident":       func(h *ActionRequest) { h.IncidentID = "incident" },
		"undo":           func(h *ActionRequest) { h.UndoOf = "earlier" },
		"TTL":            func(h *ActionRequest) { h.TTL = time.Hour },
		"not automatic":  func(h *ActionRequest) { h.Automatic = false },
		"other kind":     func(h *ActionRequest) { h.Operation = "unblock" },
		"no ID":          func(h *ActionRequest) { h.ID = "" },
		"no actor":       func(h *ActionRequest) { h.Actor = "" },
		"no source":      func(h *ActionRequest) { h.Source = "" },
		"invalid ID":     func(h *ActionRequest) { h.ID = "batch one" },
		"invalid actor":  func(h *ActionRequest) { h.Actor = "bad\xff" },
		"invalid detail": func(h *ActionRequest) { h.ActorDetail = "bad\xff" },
		"invalid source": func(h *ActionRequest) { h.Source = "bad\xff" },
	}
	for name, change := range headers {
		t.Run(name, func(t *testing.T) {
			e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
			h := batchHeader()
			change(&h)
			if _, err := e.BlockBatchRequest(h, two, nil); err == nil || errors.Is(err, errBatchPlanStop) || len(s.admitted) != 0 {
				t.Fatalf("invalid header admitted or refused for another reason: %v", err)
			}
		})
	}
	for name, members := range map[string][]ActionRequest{"no members": nil, "too many members": tooMany} {
		t.Run(name, func(t *testing.T) {
			e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
			if _, err := e.BlockBatchRequest(batchHeader(), members, nil); err == nil || errors.Is(err, errBatchPlanStop) || len(s.admitted) != 0 {
				t.Fatalf("invalid batch admitted or refused for another reason: %v", err)
			}
		})
	}
}

func TestBlockBatchRefusesInDryRun(t *testing.T) {
	e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
	e.SetDryRunEnabledFunc(func() bool { return true })
	two := []ActionRequest{batchMember("member-a", "203.0.113.20"), batchMember("member-b", "203.0.113.21")}
	if _, err := e.BlockBatchRequest(batchHeader(), two, nil); !errors.Is(err, ErrActionDryRun) || len(s.admitted) != 0 {
		t.Fatalf("dry run = %v, admitted %d", err, len(s.admitted))
	}
}

func TestBlockBatchReplaysAStoredBatch(t *testing.T) {
	a, b := batchMember("member-a", "203.0.113.20"), batchMember("member-b", "203.0.113.21")
	stored := FirewallAction{Request: batchHeader(), Members: []ActionMember{{Request: a}, {Request: b}}, Phase: "verified", AuditVersion: 2, AuditAck: 2}
	for name, tc := range map[string]struct {
		members []ActionRequest
		want    error
	}{
		"same members around a refused one": {[]ActionRequest{batchMember("member-bad", "not-an-ip"), a, b}, nil},
		"canonical spelling":                {[]ActionRequest{a, batchMember("member-b", "::ffff:203.0.113.21")}, nil},
		"other order":                       {[]ActionRequest{b, a}, ErrStateConflict},
		"duplicate admitted ID":             {[]ActionRequest{a, a, b}, nil},
		"changed admitted ID before":        {[]ActionRequest{batchMember("member-a", "203.0.113.29"), a, b}, nil},
		"changed admitted ID after":         {[]ActionRequest{a, b, batchMember("member-a", "203.0.113.29")}, nil},
		"new valid ID is not admitted":      {[]ActionRequest{a, batchMember("new-member", "203.0.113.29"), b}, nil},
		"missing member":                    {[]ActionRequest{a}, ErrStateConflict},
		"changed member":                    {[]ActionRequest{a, batchMember("member-b", "203.0.113.22")}, ErrStateConflict},
	} {
		t.Run(name, func(t *testing.T) {
			e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
			s.stored[stored.Request.ID] = stored
			result, err := e.BlockBatchRequest(batchHeader(), tc.members, nil)
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) || len(s.admitted) != 0 {
				t.Fatalf("replay = %v, want %v; admitted %d", err, tc.want, len(s.admitted))
			}
			if tc.want == nil && (result.Action.Request != stored.Request || result.Refusals != nil) {
				t.Fatalf("replay result = %#v", result)
			}
		})
	}
	t.Run("a stored action without members under the batch ID", func(t *testing.T) {
		e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
		s.stored["batch-one"] = FirewallAction{Request: batchHeader(), Phase: "verified"}
		if _, err := e.BlockBatchRequest(batchHeader(), []ActionRequest{a, b}, nil); !errors.Is(err, ErrStateConflict) || len(s.admitted) != 0 {
			t.Fatalf("batch over a stored action without members = %v", err)
		}
	})
	t.Run("a changed header", func(t *testing.T) {
		e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
		s.stored[stored.Request.ID] = stored
		changed := batchHeader()
		changed.ActorDetail = "other"
		if _, err := e.BlockBatchRequest(changed, []ActionRequest{a, b}, nil); !errors.Is(err, ErrStateConflict) || len(s.admitted) != 0 {
			t.Fatalf("changed header over a stored batch = %v", err)
		}
	})
	t.Run("a stored request under the batch ID", func(t *testing.T) {
		e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
		s.stored["batch-one"] = FirewallAction{Request: ActionRequest{ID: "batch-one", Operation: "block", Target: "203.0.113.9", Actor: "auto", Source: "scan", Automatic: true, TTL: time.Hour}, Phase: "verified"}
		if _, err := e.BlockBatchRequest(batchHeader(), []ActionRequest{a, b}, nil); !errors.Is(err, ErrStateConflict) || len(s.admitted) != 0 {
			t.Fatalf("batch over a stored request = %v", err)
		}
	})
}

func TestBlockBatchRefusesFailedLeaseCheckpoint(t *testing.T) {
	e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
	cause := errors.New("fixture checkpoint unavailable")
	e.SetBootClock(func() (string, time.Duration, error) { return "", 0, cause })
	two := []ActionRequest{batchMember("member-a", "203.0.113.20"), batchMember("member-b", "203.0.113.21")}
	if _, err := e.BlockBatchRequest(batchHeader(), two, nil); !errors.Is(err, cause) || len(s.admitted) != 0 {
		t.Fatalf("checkpoint failure = %v, admitted %d", err, len(s.admitted))
	}
}

func TestBlockBatchReplaysALoneMemberBeforeNewPolicy(t *testing.T) {
	a := batchMember("member-a", "203.0.113.20")
	bad := batchMember("member-bad", "not-an-ip")
	for _, phase := range []string{"verified", "failed"} {
		t.Run(phase, func(t *testing.T) {
			e, s := batchPlanEngine(t, FirewallConfig{DenyTempIPLimit: 1, InfraIPs: []string{a.Target}}, FirewallState{})
			stored := FirewallAction{Request: a, Phase: phase, AuditVersion: 2, AuditAck: 2}
			s.stored[a.ID] = stored
			got, err := e.BlockBatchRequest(batchHeader(), []ActionRequest{bad, a, a, batchMember("new-member", "203.0.113.29")}, nil)
			want := error(nil)
			if phase == "failed" {
				want = ErrActionFailed
			}
			if !errors.Is(err, want) || got.Action.Request != a || got.Action.Phase != phase || got.Refusals != nil || len(s.admitted) != 0 {
				t.Fatalf("singleton replay = %#v, %v; admissions %d", got, err, len(s.admitted))
			}
			if _, exists := s.stored[batchHeader().ID]; exists {
				t.Fatal("singleton unexpectedly reserved its header")
			}
		})
	}
	for name, members := range map[string][]ActionRequest{
		"changed request": {batchMember(a.ID, "203.0.113.29")},
	} {
		t.Run(name, func(t *testing.T) {
			e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
			s.stored[a.ID] = FirewallAction{Request: a, Phase: "verified"}
			if _, err := e.BlockBatchRequest(batchHeader(), members, nil); !errors.Is(err, ErrStateConflict) || len(s.admitted) != 0 {
				t.Fatalf("singleton identity changed: %v, admissions %d", err, len(s.admitted))
			}
		})
	}
}

func TestBlockBatchSingletonReplayRejectsOtherKinds(t *testing.T) {
	for name, change := range map[string]func(*ActionRequest){
		"unblock":   func(m *ActionRequest) { m.Operation = "unblock" },
		"manual":    func(m *ActionRequest) { m.Automatic = false },
		"permanent": func(m *ActionRequest) { m.TTL = 0 },
		"undo":      func(m *ActionRequest) { m.UndoOf = "earlier" },
	} {
		t.Run(name, func(t *testing.T) {
			e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
			member := batchMember("member-a", "203.0.113.20")
			change(&member)
			s.stored[member.ID] = FirewallAction{Request: member, Phase: "verified", AuditVersion: 1, AuditAck: 1}
			got, err := e.BlockBatchRequest(batchHeader(), []ActionRequest{member}, nil)
			if !errors.Is(err, ErrStateConflict) || got.Action.Request.ID != "" || len(s.admitted) != 0 {
				t.Fatalf("wrong-kind singleton replay = %#v, %v; admissions %d", got, err, len(s.admitted))
			}
		})
	}
}

func TestBlockBatchSingletonReplayRejectsTwoStoredActions(t *testing.T) {
	a := batchMember("member-a", "203.0.113.20")
	b := batchMember("member-b", "203.0.113.21")
	for _, members := range [][]ActionRequest{{a, b}, {b, a}} {
		t.Run(members[0].ID, func(t *testing.T) {
			e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
			for _, member := range members {
				s.stored[member.ID] = FirewallAction{Request: member, Phase: "verified", AuditVersion: 1, AuditAck: 1}
			}
			got, err := e.BlockBatchRequest(batchHeader(), members, nil)
			if !errors.Is(err, ErrStateConflict) || got.Action.Request.ID != "" || len(s.admitted) != 0 {
				t.Fatalf("combined singleton replay = %#v, %v; admissions %d", got, err, len(s.admitted))
			}
		})
	}
}

func TestBlockBatchPinsLeasePlanningInstant(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, shift := range []time.Duration{-2 * time.Hour, 2 * time.Hour} {
		t.Run(shift.String(), func(t *testing.T) {
			old := BlockedEntry{IP: "203.0.113.20", Reason: "expired", BlockedAt: at.Add(-2 * time.Hour), ExpiresAt: at.Add(-time.Hour)}
			e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{Blocked: []BlockedEntry{old}})
			e.leaseClock = func() (time.Time, time.Time) { return at, at }
			e.lease = leaseReading{}
			e.expiryClock = func() time.Time { return at.Add(shift) }
			members := []ActionRequest{batchMember("member-a", old.IP), batchMember("member-b", "203.0.113.21")}
			_, err := e.BlockBatchRequest(batchHeader(), members, nil)
			if !errors.Is(err, errBatchPlanStop) || len(s.admitted) != 1 {
				t.Fatalf("clock skew poisoned batch: %v, plans %d", err, len(s.admitted))
			}
			plan := s.admitted[0]
			if !plan.CreatedAt.Equal(at) || !plan.After.Blocked[1].BlockedAt.Equal(plan.CreatedAt) {
				t.Fatalf("planning cutoff %v differs from member lease %v", plan.CreatedAt, plan.After.Blocked[1].BlockedAt)
			}
			if err := (engineActionKernel{}).ValidateEvidence(plan); err != nil {
				t.Fatalf("planner produced invalid evidence: %v", err)
			}
			if len(plan.KernelAfter[0].Elements) != 2 {
				t.Fatalf("old expired row reappeared in evidence: %#v", plan.KernelAfter)
			}
		})
	}
}

func TestBlockBatchLoneMemberPinsLeasePlanningInstant(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	old := BlockedEntry{IP: "203.0.113.20", Reason: "expired", BlockedAt: at.Add(-2 * time.Hour), ExpiresAt: at.Add(-time.Hour)}
	e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{Blocked: []BlockedEntry{old}})
	e.leaseClock = func() (time.Time, time.Time) { return at, at }
	e.lease = leaseReading{}
	e.expiryClock = func() time.Time { return at.Add(-2 * time.Hour) }
	_, err := e.BlockBatchRequest(batchHeader(), []ActionRequest{batchMember("member-a", old.IP)}, nil)
	if !errors.Is(err, errBatchPlanStop) || len(s.admitted) != 1 {
		t.Fatalf("singleton clock skew poisoned plan: %v, plans %d", err, len(s.admitted))
	}
	plan := s.admitted[0]
	if !plan.CreatedAt.Equal(at) || !plan.After.Blocked[1].BlockedAt.Equal(at) || len(plan.KernelAfter[0].Elements) != 1 {
		t.Fatalf("singleton planning clock differs from its lease: %#v", plan)
	}
	if err := (engineActionKernel{}).ValidateEvidence(plan); err != nil {
		t.Fatalf("singleton planner produced invalid evidence: %v", err)
	}
}

type batchLookupStore struct {
	*batchPlanStore
	reads       map[string]int
	failID      string
	fail        error
	transitions int
}

func (s *batchLookupStore) ReadFirewallAction(id string) (FirewallAction, error) {
	s.reads[id]++
	if id == s.failID {
		return FirewallAction{}, s.fail
	}
	return s.batchPlanStore.ReadFirewallAction(id)
}
func (s *batchLookupStore) TransitionFirewallAction(string, string, string, time.Time) (FirewallAction, error) {
	s.transitions++
	return FirewallAction{}, errors.New("unexpected transition of a terminal replay")
}

func TestBlockBatchReplayReadsEachIdentityOnce(t *testing.T) {
	for _, stored := range []bool{false, true} {
		name := "missing"
		if stored {
			name = "stored"
		}
		t.Run(name, func(t *testing.T) {
			e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
			m := batchMember("member-a", "203.0.113.20")
			counter := &batchLookupStore{batchPlanStore: s, reads: map[string]int{}}
			e.lifecycle.Store = counter
			candidates := make([]ActionRequest, MaxActionMembers)
			for i := range candidates {
				candidates[i] = m
				candidates[i].Target = "not-an-ip"
			}
			if stored {
				s.stored[m.ID] = FirewallAction{Request: m, Phase: "verified", AuditVersion: 1, AuditAck: 1}
				candidates[len(candidates)-1] = m
			}
			got, err := e.BlockBatchRequest(batchHeader(), candidates, nil)
			if err != nil || len(s.admitted) != 0 || counter.transitions != 0 {
				t.Fatalf("lookup result: %#v, %v, admissions %d, transitions %d", got, err, len(s.admitted), counter.transitions)
			}
			if stored && got.Action.Request != m {
				t.Fatalf("a later exact occurrence did not replay: %#v", got)
			}
			if !stored && (got.Action.Request.ID != "" || len(got.Refusals) != len(candidates)) {
				t.Fatalf("missing IDs produced an action: %#v", got)
			}
			if counter.reads[m.ID] != 1 || counter.reads[batchHeader().ID] != 1 {
				t.Fatalf("lookup reads = %v; want one read per identity", counter.reads)
			}
			if stored {
				changed := s.stored[m.ID]
				changed.Phase = "failed"
				s.stored[m.ID] = changed
				got, err = e.BlockBatchRequest(batchHeader(), candidates, nil)
				if !errors.Is(err, ErrActionFailed) || got.Action.Phase != "failed" || counter.reads[m.ID] != 2 {
					t.Fatalf("lookup cache escaped its call: %#v, %v, reads %v", got, err, counter.reads)
				}
			}
		})
	}
}

func TestBlockBatchReplayHandlesUnrelatedStoredActions(t *testing.T) {
	for _, exact := range []bool{false, true} {
		name := "no_exact_singleton"
		if exact {
			name = "with_exact_singleton"
		}
		t.Run(name, func(t *testing.T) {
			e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
			member := batchMember("member-a", "203.0.113.20")
			unrelated := batchMember("other-action", "203.0.113.90")
			unrelated.Operation = "unblock"
			unrelated.Automatic = false
			s.stored[unrelated.ID] = FirewallAction{Request: unrelated, Phase: "verified", AuditVersion: 1, AuditAck: 1}
			if exact {
				s.stored[member.ID] = FirewallAction{Request: member, Phase: "verified", AuditVersion: 1, AuditAck: 1}
			}
			extra := batchMember(unrelated.ID, "not-an-ip")
			counter := &batchLookupStore{batchPlanStore: s, reads: map[string]int{}}
			e.lifecycle.Store = counter
			got, err := e.BlockBatchRequest(batchHeader(), []ActionRequest{extra, member, extra}, nil)
			if exact {
				if err != nil || got.Action.Request != member || got.Refusals != nil {
					t.Fatalf("unrelated extra changed singleton replay: %#v, %v", got, err)
				}
			} else if !errors.Is(err, ErrStateConflict) || got.Action.Request.ID != "" {
				t.Fatalf("unrelated identity was reused: %#v, %v", got, err)
			}
			if len(s.admitted) != 0 || counter.transitions != 0 || counter.reads[unrelated.ID] != 1 {
				t.Fatalf("unrelated stored action was mutated or decoded twice: admissions %d, transitions %d, reads %v", len(s.admitted), counter.transitions, counter.reads)
			}
			cause := errors.New("stored action unreadable")
			counter.failID, counter.fail = unrelated.ID, cause
			if _, err := e.BlockBatchRequest(batchHeader(), []ActionRequest{member, extra}, nil); !errors.Is(err, cause) || len(s.admitted) != 0 {
				t.Fatalf("lookup failure was hidden: %v", err)
			}
		})
	}
}

func TestBlockBatchTerminalReplaySurvivesExpiry(t *testing.T) {
	for _, phase := range []string{"verified", "failed"} {
		t.Run(phase, func(t *testing.T) {
			a := batchEvidence()
			a.Phase = phase
			a.AuditAck = a.AuditVersion
			current := a.After
			if phase == "failed" {
				current = a.Before
			}
			e, s := batchPlanEngine(t, FirewallConfig{}, current)
			e.expiryClock = func() time.Time { return a.CreatedAt.Add(2 * time.Hour) }
			s.stored[a.Request.ID] = a
			counter := &batchLookupStore{batchPlanStore: s, reads: map[string]int{}}
			e.lifecycle.Store = counter
			members := []ActionRequest{a.Members[0].Request, a.Members[1].Request}
			got, err := e.BlockBatchRequest(a.Request, members, nil)
			want := error(nil)
			if phase == "failed" {
				want = ErrActionFailed
			}
			if !errors.Is(err, want) || got.Action.Phase != phase || got.Action.AuditVersion != a.AuditVersion || got.Refusals != nil || len(s.admitted) != 0 || counter.transitions != 0 {
				t.Fatalf("expiry rewrote terminal outcome: %#v, %v, transitions %d", got, err, counter.transitions)
			}
		})
	}
}

func TestBlockBatchRefactorKeepsSingleRequestClock(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
	wall := at.Add(-2 * time.Hour)
	e.leaseClock = func() (time.Time, time.Time) { return at, at }
	e.lease = leaseReading{}
	e.expiryClock = func() time.Time { return wall }
	next := FirewallState{Blocked: []BlockedEntry{{IP: "203.0.113.20", BlockedAt: at, ExpiresAt: at.Add(time.Hour)}}}
	e.mu.Lock()
	err := e.runDurableLocked(batchMember("single", "203.0.113.20"), nil, next)
	e.mu.Unlock()
	if !errors.Is(err, errBatchPlanStop) || len(s.admitted) != 1 {
		t.Fatalf("single request plan: %v, admissions %d", err, len(s.admitted))
	}
	plan := s.admitted[0]
	if !plan.CreatedAt.Equal(wall) || plan.Members != nil || !plan.After.Blocked[0].BlockedAt.Equal(at) {
		t.Fatalf("batch refactor changed the single-request clock: %#v", plan)
	}
}

type batchPendingStore struct{ *batchPlanStore }

func (s batchPendingStore) PendingFirewallActions() ([]FirewallAction, error) {
	return []FirewallAction{{Request: ActionRequest{ID: "held"}}}, nil
}

// A refusal before admission keeps the single-request path's refusal record:
// nothing was admitted, so no durable outcome speaks for the attempt.
func TestBlockBatchRefactorKeepsSingleRequestRefusals(t *testing.T) {
	committed := FirewallState{Blocked: []BlockedEntry{{IP: "203.0.113.21", Reason: "brute force", Source: "scan", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}}}
	for _, tc := range []struct {
		name    string
		prepare func(*Engine, *batchPlanStore)
	}{
		{"live set differs", func(_ *Engine, s *batchPlanStore) { s.state = committed }},
		{"pending action", func(e *Engine, s *batchPlanStore) { e.lifecycle.Store = batchPendingStore{s} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
			tc.prepare(e, s)
			e.mu.Lock()
			err := e.runDurableLocked(ActionRequest{Operation: "unblock", Target: "203.0.113.21", Actor: "cli", Source: "cli"}, nil, FirewallState{})
			e.mu.Unlock()
			if !errors.Is(err, ErrActionUnknown) || !e.shouldLegacyOutcome(err) || len(s.admitted) != 0 {
				t.Fatalf("refusal before admission: %v, legacy record %t, admissions %d", err, e.shouldLegacyOutcome(err), len(s.admitted))
			}
		})
	}
}

// An admitted action speaks for its own outcome, so the public boundary
// must not add a refusal record for it.
func TestBlockBatchRefactorKeepsAdmittedOutcomes(t *testing.T) {
	e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
	req := ActionRequest{ID: "single-failed", Operation: "unblock", Target: "203.0.113.22", Actor: "cli", Source: "cli"}
	s.stored[req.ID] = FirewallAction{Request: req, Phase: "failed"}
	e.mu.Lock()
	err := e.runDurableLocked(req, nil, FirewallState{})
	e.mu.Unlock()
	if !errors.Is(err, ErrActionFailed) || e.shouldLegacyOutcome(err) {
		t.Fatalf("admitted failure: %v, legacy record %t", err, e.shouldLegacyOutcome(err))
	}
}

// Expiry cannot settle an unverified row: its address stays pending until
// its owner proves the outcome, as the store's batch-state rule requires.
func TestBlockBatchHoldsExpiredUnverifiedRows(t *testing.T) {
	at := time.Now().Round(0)
	committed := FirewallState{Blocked: []BlockedEntry{
		{IP: "203.0.113.47", Reason: "unproven", BlockedAt: at.Add(-2 * time.Hour), ExpiresAt: at.Add(-time.Hour), ActionID: "earlier-one", Unverified: true},
		{IP: "::ffff:203.0.113.48", Reason: "unproven alias", BlockedAt: at.Add(-2 * time.Hour), ExpiresAt: at.Add(-time.Hour), ActionID: "earlier-two", Unverified: true},
	}}
	e, s := batchPlanEngine(t, FirewallConfig{}, committed)
	members := []ActionRequest{
		batchMember("member-held", "203.0.113.47"),
		batchMember("member-alias", "203.0.113.48"),
		batchMember("member-free-a", "203.0.113.49"),
		batchMember("member-free-b", "203.0.113.50"),
	}
	result, err := e.BlockBatchRequest(batchHeader(), members, nil)
	want := []BlockRefusal{BlockRefusedPending, BlockRefusedPending, "", ""}
	if !errors.Is(err, errBatchPlanStop) || fmt.Sprint(result.Refusals) != fmt.Sprint(want) {
		t.Fatalf("expired unverified rows = %q, %v; want %q", result.Refusals, err, want)
	}
	if plan := s.admitted[0]; len(plan.Members) != 2 || len(plan.After.Blocked) != 4 || !plan.After.Blocked[0].Unverified {
		t.Fatalf("plan = members %#v, after %#v", plan.Members, plan.After.Blocked)
	}
}

type batchChangingStateStore struct {
	*batchPlanStore
	revision uint64
	reads    int
	onRead   func(int)
}

func (s *batchChangingStateStore) ReadFirewallState() (FirewallState, uint64, error) {
	state, revision := s.state, s.revision
	s.reads++
	if s.onRead != nil {
		s.onRead(s.reads)
	}
	return state, revision, nil
}

func TestBlockBatchRejectsRevisionChangedDuringMemberChecks(t *testing.T) {
	for _, count := range []int{1, 2} {
		t.Run(fmt.Sprintf("members_%d", count), func(t *testing.T) {
			e, base := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
			s := &batchChangingStateStore{batchPlanStore: base, revision: 7}
			e.lifecycle.Store = s
			s.onRead = func(reads int) {
				if reads == 2 {
					// Commit after the readiness and planning reads, before the
					// first member check. The old After must not gain this revision.
					s.state = FirewallState{PortAllowed: []PortAllowEntry{{IP: "192.0.2.90", Port: 443, Proto: "tcp"}}}
					s.revision++
				}
			}
			members := []ActionRequest{batchMember("member-a", "203.0.113.20"), batchMember("member-b", "203.0.113.21")}
			got, err := e.BlockBatchRequest(batchHeader(), members[:count], nil)
			if !errors.Is(err, ErrStateConflict) || len(s.admitted) != 0 || got.Action.Request.ID != "" {
				t.Fatalf("stale batch = %#v, %v; admissions %d", got, err, len(s.admitted))
			}
		})
	}
}

func TestBlockBatchChecksAllowsFromPlanningSnapshot(t *testing.T) {
	state := FirewallState{
		Allowed:     []AllowedEntry{{IP: "::ffff:203.0.113.20", Reason: "operator"}},
		PortAllowed: []PortAllowEntry{{IP: "::ffff:203.0.113.21", Port: 443, Proto: "tcp"}},
	}
	e, base := batchPlanEngine(t, FirewallConfig{}, state)
	s := &batchChangingStateStore{batchPlanStore: base, revision: 7}
	e.lifecycle.Store = s
	s.onRead = func(reads int) {
		if reads == 2 {
			s.state = FirewallState{}
			s.revision++
		}
	}
	members := []ActionRequest{batchMember("member-a", "203.0.113.20"), batchMember("member-b", "203.0.113.21")}
	got, err := e.BlockBatchRequest(batchHeader(), members, nil)
	want := []BlockRefusal{BlockRefusedAllowed, BlockRefusedAllowed}
	if err != nil || fmt.Sprint(got.Refusals) != fmt.Sprint(want) || len(s.admitted) != 0 || got.Action.Request.ID != "" {
		t.Fatalf("snapshot allows = %#v, %v; admissions %d", got, err, len(s.admitted))
	}
}

func TestBlockBatchUnverifiedAliasHoldsAddress(t *testing.T) {
	at := time.Now().Round(0)
	unverified := BlockedEntry{IP: "::ffff:203.0.113.20", ExpiresAt: at.Add(-time.Hour), Unverified: true, ActionID: "unsettled"}
	verified := BlockedEntry{IP: "203.0.113.20", ExpiresAt: at.Add(2 * time.Hour)}
	for _, unverifiedFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("unverified_first_%t", unverifiedFirst), func(t *testing.T) {
			rows := []BlockedEntry{verified, unverified}
			if unverifiedFirst {
				rows = []BlockedEntry{unverified, verified}
			}
			e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{Blocked: rows})
			members := []ActionRequest{batchMember("member-a", verified.IP), batchMember("member-b", "203.0.113.21")}
			got, err := e.BlockBatchRequest(batchHeader(), members, nil)
			want := []BlockRefusal{BlockRefusedPending, ""}
			if !errors.Is(err, errBatchPlanStop) || fmt.Sprint(got.Refusals) != fmt.Sprint(want) || len(s.admitted) != 1 {
				t.Fatalf("unverified alias = %q, %v; admissions %d", got.Refusals, err, len(s.admitted))
			}
			plan := s.admitted[0]
			if plan.Request != members[1] || plan.Members != nil || len(plan.After.Blocked) != 3 || !SameBlockedEntry(plan.After.Blocked[0], rows[0]) || !SameBlockedEntry(plan.After.Blocked[1], rows[1]) {
				t.Fatalf("unverified address was changed: request %#v, rows %#v", plan.Request, plan.After.Blocked)
			}
		})
	}
}

func TestBlockBatchAllowExpiryUsesWallSnapshot(t *testing.T) {
	at := time.Now().Round(0)
	state := FirewallState{Allowed: []AllowedEntry{
		{IP: "203.0.113.20", ExpiresAt: at.Add(time.Minute)},
		{IP: "::ffff:203.0.113.21", ExpiresAt: at},
	}}
	e, s := batchPlanEngine(t, FirewallConfig{}, state)
	wall := at
	e.expiryClock = func() time.Time { return wall }
	e.leaseClock = func() (time.Time, time.Time) {
		// Member checks must keep the sampled wall instant, even when time
		// passes and the block lease is ahead after an earlier clock step.
		wall = at.Add(2 * time.Minute)
		return at.Add(time.Hour), at
	}
	members := []ActionRequest{
		batchMember("member-allowed", "203.0.113.20"),
		batchMember("member-expired-allow", "203.0.113.21"),
		batchMember("member-free", "203.0.113.22"),
	}
	got, err := e.BlockBatchRequest(batchHeader(), members, nil)
	want := []BlockRefusal{BlockRefusedAllowed, "", ""}
	if !errors.Is(err, errBatchPlanStop) || fmt.Sprint(got.Refusals) != fmt.Sprint(want) || len(s.admitted) != 1 {
		t.Fatalf("allow expiry = %q, %v; admissions %d", got.Refusals, err, len(s.admitted))
	}
	plan := s.admitted[0]
	if len(plan.Members) != 2 || plan.Members[0].Request != members[1] || plan.Members[1].Request != members[2] || !plan.CreatedAt.Equal(at.Add(time.Hour)) {
		t.Fatalf("allow expiry changed the planned members: %#v", plan)
	}
}
