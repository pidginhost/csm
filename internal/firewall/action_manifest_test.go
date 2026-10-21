package firewall

import (
	"errors"
	"testing"
	"time"
)

func manifestBatch() FirewallAction {
	expires := time.Date(2026, 1, 2, 4, 0, 0, 0, time.UTC)
	header := ActionRequest{ID: "batch-one", Operation: "block", Actor: "auto", Source: "scan", Automatic: true}
	member := func(id, target string) ActionMember {
		return ActionMember{Request: ActionRequest{ID: id, Operation: "block", Target: target, Reason: "brute force", Actor: "auto", Source: "scan", Automatic: true, TTL: time.Hour}}
	}
	first, second := member("member-one", "203.0.113.10"), member("member-two", "203.0.113.11")
	first.Victims = []BlockedEntry{{IP: "203.0.113.99", Reason: "older", Source: "scan", BlockedAt: expires.Add(-2 * time.Hour), ExpiresAt: expires}}
	return FirewallAction{Request: header, Members: []ActionMember{first, second}}
}

func TestActionMembersDerivesOneMemberForEarlierRecords(t *testing.T) {
	req := ActionRequest{ID: "request-one", Operation: "unblock", Target: "203.0.113.90", Actor: "cli", Source: "scan"}
	budget := &ScanAdmission{Window: "2026-01-02T03", Limit: 1}
	members := FirewallAction{Request: req, Budget: budget}.ActionMembers()
	if len(members) != 1 || members[0].Request != req || members[0].Budget != budget || members[0].Victims != nil {
		t.Fatalf("members = %#v", members)
	}
	batch := manifestBatch()
	if got := batch.ActionMembers(); len(got) != 2 || got[1].Request.ID != "member-two" {
		t.Fatalf("batch members = %#v", got)
	}
}

func TestSameManifestComparesHeaderMembersOrderAndEffects(t *testing.T) {
	a := manifestBatch()
	b := manifestBatch()
	b.Members[0].Budget = &ScanAdmission{Window: "2026-01-02T05", Limit: 9}
	if !a.SameManifest(b) {
		t.Fatal("admission data changed the manifest")
	}
	b = manifestBatch()
	b.Members[1].Victims = []BlockedEntry{}
	if !a.SameManifest(b) {
		t.Fatal("an empty victim list differs from none")
	}
	changes := map[string]func(*FirewallAction){
		"header":       func(x *FirewallAction) { x.Request.Actor = "other" },
		"member order": func(x *FirewallAction) { x.Members[0], x.Members[1] = x.Members[1], x.Members[0] },
		"membership":   func(x *FirewallAction) { x.Members = x.Members[:1] },
		"member":       func(x *FirewallAction) { x.Members[1].Request.TTL = 2 * time.Hour },
		"victim": func(x *FirewallAction) {
			x.Members[0].Victims[0].ExpiresAt = x.Members[0].Victims[0].ExpiresAt.Add(time.Second)
		},
		"victim added": func(x *FirewallAction) { x.Members[1].Victims = append(x.Members[1].Victims, x.Members[0].Victims[0]) },
	}
	for name, change := range changes {
		b := manifestBatch()
		change(&b)
		if a.SameManifest(b) || b.SameManifest(a) {
			t.Errorf("%s change kept the manifest", name)
		}
	}
	req := ActionRequest{ID: "request-one", Operation: "unblock", Target: "203.0.113.90", Actor: "cli", Source: "scan"}
	earlier := FirewallAction{Request: req, Budget: &ScanAdmission{Window: "2026-01-02T03", Limit: 1}}
	explicit := FirewallAction{Request: req, Members: []ActionMember{{Request: req}}}
	if !earlier.SameManifest(explicit) || !explicit.SameManifest(earlier) {
		t.Fatal("an earlier record differs from its one-member manifest")
	}
}

func TestSameManifestComparesVictimTimesByInstant(t *testing.T) {
	for name, field := range map[string]func(*BlockedEntry) *time.Time{
		"blocked at": func(v *BlockedEntry) *time.Time { return &v.BlockedAt },
		"expires at": func(v *BlockedEntry) *time.Time { return &v.ExpiresAt },
	} {
		t.Run(name, func(t *testing.T) {
			a, b := manifestBatch(), manifestBatch()
			left, right := field(&a.Members[0].Victims[0]), field(&b.Members[0].Victims[0])
			*right = left.In(time.FixedZone("offset", 3600))
			if !a.SameManifest(b) || !b.SameManifest(a) {
				t.Error("the same instant with a different offset changed the manifest")
			}
			*right = right.Add(time.Nanosecond)
			if a.SameManifest(b) || b.SameManifest(a) {
				t.Error("a changed instant kept the manifest")
			}
			*left = time.Now()
			*right = left.Round(0)
			if !a.SameManifest(b) || !b.SameManifest(a) {
				t.Error("removing monotonic clock data changed the manifest")
			}
		})
	}
}

func TestSameManifestComparesVictimMetadataExactly(t *testing.T) {
	for name, field := range map[string]func(*BlockedEntry) *string{
		"ip":        func(v *BlockedEntry) *string { return &v.IP },
		"reason":    func(v *BlockedEntry) *string { return &v.Reason },
		"source":    func(v *BlockedEntry) *string { return &v.Source },
		"action id": func(v *BlockedEntry) *string { return &v.ActionID },
	} {
		t.Run(name, func(t *testing.T) {
			a, b := manifestBatch(), manifestBatch()
			left, right := field(&a.Members[0].Victims[0]), field(&b.Members[0].Victims[0])
			*right += "changed"
			if a.SameManifest(b) || b.SameManifest(a) {
				t.Error("changed victim metadata kept the manifest")
			}
			// JSON replaces both distinct bytes with the same replacement rune.
			*left, *right = "value\xff", "value\xfe"
			if a.SameManifest(b) || b.SameManifest(a) {
				t.Error("distinct victim bytes kept the manifest")
			}
		})
	}
	a, b := manifestBatch(), manifestBatch()
	b.Members[0].Victims[0].Unverified = true
	if a.SameManifest(b) || b.SameManifest(a) {
		t.Fatal("changed victim verification status kept the manifest")
	}
}

func TestIsRequestAcceptsOnlyTheOneMemberAction(t *testing.T) {
	req := ActionRequest{ID: "request-one", Operation: "unblock", Target: "203.0.113.90", Actor: "cli", Source: "scan"}
	if !(FirewallAction{Request: req}).IsRequest(req) {
		t.Fatal("an earlier record is not its request")
	}
	if !(FirewallAction{Request: req, Members: []ActionMember{{Request: req}}}).IsRequest(req) {
		t.Fatal("a one-member manifest is not its request")
	}
	other := req
	other.Reason = "changed"
	if (FirewallAction{Request: req}).IsRequest(other) {
		t.Fatal("a changed request matched")
	}
	if (FirewallAction{Request: req, Members: []ActionMember{{Request: other}}}).IsRequest(req) {
		t.Fatal("a member that differs from its header matched")
	}
	batch := manifestBatch()
	if batch.IsRequest(batch.Request) {
		t.Fatal("a batch matched its header as one request")
	}
	if (FirewallAction{Request: req, Members: []ActionMember{{Request: req}, {Request: other}}}).IsRequest(req) {
		t.Fatal("a batch led by the request matched as one request")
	}
}

type manifestReadStore struct {
	ActionStore
	action FirewallAction
}

func (s manifestReadStore) ReadFirewallAction(id string) (FirewallAction, error) {
	if id != s.action.Request.ID {
		return FirewallAction{}, ErrActionMissing
	}
	return s.action, nil
}

func TestUndoReplayRefusesABatchWithTheSameHeader(t *testing.T) {
	req := ActionRequest{ID: "undo-one", Operation: "undo", UndoOf: "batch-one", Actor: "cli", Source: "cli"}
	batch := manifestBatch()
	batch.Request = req
	l := &Lifecycle{Store: manifestReadStore{action: batch}}
	if _, err := l.Undo(req, nil); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("undo replay of a batch = %v, want conflict", err)
	}
}

func (s manifestReadStore) AdmitFirewallAction(FirewallAction) (FirewallAction, bool, error) {
	return FirewallAction{}, false, errors.New("unexpected batch replay execution")
}
