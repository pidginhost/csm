package firewall

import (
	"errors"
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

// FirewallAction retains both complete states until the kernel outcome can be
// proved. Admission does not publish After as committed firewall state.
type FirewallAction struct {
	Ruleset      *ActionRuleset `json:"ruleset,omitempty"`
	KernelBefore []ActionSet    `json:"kernel_before,omitempty"`
	KernelAfter  []ActionSet    `json:"kernel_after,omitempty"`
	Request      ActionRequest  `json:"request"`
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
