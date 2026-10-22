package firewall

import (
	"errors"
	"net"
	"slices"
	"sync"
	"time"
)

var (
	ErrActionDryRun       = errors.New("firewall action suppressed by dry-run policy")
	ErrActionAuditPending = errors.New("firewall action verified; audit delivery pending")
	ErrActionMissing      = errors.New("firewall action not found")
	ErrActionUnknown      = errors.New("firewall action outcome requires recovery")
	ErrActionFailed       = errors.New("firewall action was not applied")
	ErrScanBudget         = errors.New("firewall scan budget exhausted")
)

// ActionRequest is the identity and policy input for one firewall decision.
// ID identifies a request, not an individual attempt to contact the kernel.
type ActionRequest struct {
	ID          string        `json:"id"`
	Operation   string        `json:"operation"`
	Target      string        `json:"target"`
	Reason      string        `json:"reason"`
	Actor       string        `json:"actor"`
	ActorDetail string        `json:"actor_detail,omitempty"`
	Source      string        `json:"source"`
	FindingID   string        `json:"finding_id,omitempty"`
	IncidentID  string        `json:"incident_id,omitempty"`
	UndoOf      string        `json:"undo_of,omitempty"`
	Automatic   bool          `json:"automatic,omitempty"`
	TTL         time.Duration `json:"ttl,omitempty"`
}

// ScanAdmission uses the existing scan hourly policy. A nil admission is
// exempt; callers must not charge non-scan sources to the scan budget.
type ScanAdmission struct {
	Window string `json:"window"`
	Limit  int    `json:"limit"`
}

// MaxActionMembers bounds one batch manifest. It matches the block batch
// applier, so one durable batch can carry one applier batch.
const MaxActionMembers = MaxBlockBatchMembers

// ActionMember is one immutable single-target request inside a batch, with
// its admission data and the effects its plan records.
type ActionMember struct {
	Request ActionRequest  `json:"request"`
	Budget  *ScanAdmission `json:"budget,omitempty"`
	// Victims are the rows this member removes to make room, exactly as they
	// were, so undo can prove they are still current.
	Victims []BlockedEntry `json:"victims,omitempty"`
}

// FirewallAction retains both complete states until the kernel outcome can be
// proved. Admission does not publish After as committed firewall state.
type FirewallAction struct {
	Ruleset      *ActionRuleset `json:"ruleset,omitempty"`
	KernelBefore []ActionSet    `json:"kernel_before,omitempty"`
	KernelAfter  []ActionSet    `json:"kernel_after,omitempty"`
	Request      ActionRequest  `json:"request"`
	// Members is the batch manifest. Without it the action is one member, its
	// Request and Budget, as every record written before manifests is. With
	// it, a batch of several members uses Request as its header.
	Members      []ActionMember `json:"members,omitempty"`
	Before       FirewallState  `json:"before"`
	After        FirewallState  `json:"after"`
	Revision     uint64         `json:"revision"`
	Phase        string         `json:"phase"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	Detail       string         `json:"detail,omitempty"`
	Budget       *ScanAdmission `json:"budget,omitempty"`
	AuditVersion uint64         `json:"audit_version"`
	AuditAck     uint64         `json:"audit_ack"`
}

// ActionMembers returns the batch manifest, deriving the single member of an
// action that carries none. Callers must not modify the result.
func (a FirewallAction) ActionMembers() []ActionMember {
	if a.Members == nil {
		return []ActionMember{{Request: a.Request, Budget: a.Budget}}
	}
	return a.Members
}

// SameManifest reports whether b is the same batch as a: the same header, the
// same members in the same order and the same effects. Admission data is not
// compared: a replay in a later window keeps the charge taken first.
func (a FirewallAction) SameManifest(b FirewallAction) bool {
	return a.Request == b.Request && slices.EqualFunc(a.ActionMembers(), b.ActionMembers(), func(x, y ActionMember) bool {
		return x.Request == y.Request && slices.EqualFunc(x.Victims, y.Victims, SameBlockedEntry)
	})
}

// removedVictims returns the victims of m that a took out: rows its Before
// state held exactly, at an address no row of its After state names. A batch
// keeps every unexpired row, so a victim stored on a batch member was never
// evicted; it is neither audited as an eviction nor restored by undo.
func removedVictims(a FirewallAction, m ActionMember) []BlockedEntry {
	if len(a.Members) > 1 {
		return nil
	}
	var out []BlockedEntry
	for _, v := range m.Victims {
		held := slices.ContainsFunc(a.Before.Blocked, func(row BlockedEntry) bool { return SameBlockedEntry(row, v) })
		kept := slices.ContainsFunc(a.After.Blocked, func(row BlockedEntry) bool { return sameAddress(row.IP, v.IP) })
		if held && !kept {
			out = append(out, v)
		}
	}
	return out
}

// sameAddress reports whether two spellings name one IP address.
func sameAddress(a, b string) bool {
	x := net.ParseIP(a)
	return x != nil && x.Equal(net.ParseIP(b))
}

// IsRequest reports whether a is the one-member action for exactly req, so a
// batch whose header happens to match is never replayed as one request.
func (a FirewallAction) IsRequest(req ActionRequest) bool {
	members := a.ActionMembers()
	return a.Request == req && len(members) == 1 && members[0].Request == req
}

// ActionStore owns atomic admission, accounting, outcome and audit delivery
// state. Implementations must keep kernel and audit I/O outside transactions.
type ActionStore interface {
	StateStore
	AdmitFirewallAction(FirewallAction) (FirewallAction, bool, error)
	ReadFirewallAction(string) (FirewallAction, error)
	PendingFirewallActions() ([]FirewallAction, error)
	TransitionFirewallAction(string, string, string, time.Time) (FirewallAction, error)
	FirewallAuditPending() ([]FirewallAction, error)
	AcknowledgeFirewallAudit(string, uint64) error
	ReadFirewallScanBudget(string) (int, error)
}

type ActionObservation struct{ Before, After bool }

// ActionKernel compares the affected targets, including provenance and expiry.
// Recovery only observes; it never calls ApplyFirewallAction.
type ActionKernel interface {
	ObserveFirewallAction(FirewallAction) (ActionObservation, error)
	ApplyFirewallAction(FirewallAction) error
}

// Lifecycle is owned by one engine. Its lock serializes execution with recovery
// and undo, while the store protects admission against competing requests.
type Lifecycle struct {
	mu    sync.Mutex
	Store ActionStore
	Audit func(FirewallAction) error
}

// ActionSet is detached recovery evidence for one complete nftables set.
// Expiry is absolute so neither retry nor undo can renew a timed element.
type ActionSet struct {
	Exists   bool            `json:"exists"`
	Name     string          `json:"name"`
	Elements []ActionElement `json:"elements"`
}
type ActionElement struct {
	Key       []byte    `json:"key"`
	End       bool      `json:"end,omitempty"`
	Comment   string    `json:"comment,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// ActionRuleset proves an atomic whole-ruleset application. An unrelated
// namespace edit invalidates this conservative recovery proof.
type ActionRuleset struct {
	Generation uint32 `json:"generation_before"`
	Marker     string `json:"marker"`
}
