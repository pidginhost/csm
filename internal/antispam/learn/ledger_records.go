package learn

import "time"

// Binding ties the ledger to one hash-key generation and storage prefix.
type Binding struct {
	HashGeneration string    `json:"hash_generation"`
	Prefix         string    `json:"prefix"`
	Created        time.Time `json:"created"`
}

// Cluster is one anchored cluster: an immutable anchor digest and body, its
// contributors and accepted aliases.
type Cluster struct {
	ID         uint64    `json:"id"`
	Anchor     Digest    `json:"anchor"`
	BodyLen    int64     `json:"body_len"`
	BodySHA    string    `json:"body_sha"`
	UIDs       []int     `json:"uids,omitempty"`
	Marks      []string  `json:"marks,omitempty"`
	Aliases    []Digest  `json:"aliases,omitempty"`
	Revision   uint64    `json:"revision"`
	Created    time.Time `json:"created"`
	LastReport time.Time `json:"last_report"`
	// Operator: created by an operator request, charged to the operator
	// allowance.
	Operator bool `json:"operator,omitempty"`
	// Charges is what each contributor was charged for this cluster.
	// A retired cluster holds only the charges still awaiting cleanup.
	Charges []Charge `json:"charges,omitempty"`
	// Retired: the zero target is durable; the record stays only as the
	// cleanup reference until the body is unlinked.
	Retired bool `json:"retired,omitempty"`
}

// Charge is one contributor's charge for one cluster.
type Charge struct {
	UID      int   `json:"uid"`
	Operator bool  `json:"operator,omitempty"`
	Usage    Usage `json:"usage"`
}

// Phase is a target's publication phase (spec 7.4 "Publishing a target").
type Phase string

// Publication phases. The phase is persisted before every native send.
const (
	PhaseIdle          Phase = "idle"
	PhaseRead          Phase = "read"
	PhaseAddSent       Phase = "add_sent"
	PhaseDeletePending Phase = "delete_pending"
	PhaseDeleteSent    Phase = "delete_sent"
	PhaseAddPending    Phase = "add_pending"
)

// Target is the one current target per digest; T=0 is a zero-target guard.
type Target struct {
	Digest       Digest    `json:"digest"`
	ClusterID    uint64    `json:"cluster_id"`
	T            int32     `json:"t"`
	Revision     uint64    `json:"revision"`
	Phase        Phase     `json:"phase"`
	ResetPending bool      `json:"reset_pending,omitempty"`
	RestoreT     int32     `json:"restore_t,omitempty"`
	Updated      time.Time `json:"updated"`
	// GuardCharge remains after body cleanup because a zero-target guard
	// cannot be evicted to free capacity.
	GuardCharge *Charge `json:"guard_charge,omitempty"`
	// SentRevision is the revision of the last journaled native write. A
	// reservation it has not reached has sent nothing.
	SentRevision uint64 `json:"sent_revision,omitempty"`
}

// IntentKind names what an intent does.
type IntentKind string

// Intent kinds.
const (
	IntentReport   IntentKind = "report"
	IntentOperator IntentKind = "operator_spam"
	IntentForget   IntentKind = "forget"
	IntentRetire   IntentKind = "retire"
)

// Seed is a new cluster's anchor and first target. Staged, BodyLen and
// BodySHA name the anchor body staged for it.
type Seed struct {
	Anchor  Digest `json:"anchor"`
	T       int32  `json:"t"`
	Staged  string `json:"staged,omitempty"`
	BodyLen int64  `json:"body_len,omitempty"`
	BodySHA string `json:"body_sha,omitempty"`
}

// IntentCluster is one cluster an intent changes, committed separately.
type IntentCluster struct {
	ClusterID uint64   `json:"cluster_id"`
	Anchor    Digest   `json:"anchor"`
	Revision  uint64   `json:"revision"`
	Aliases   []Digest `json:"aliases,omitempty"`
	NewT      int32    `json:"new_t"`
	Done      bool     `json:"done,omitempty"`
	// Prior is the target this reservation replaced, restored if the
	// reservation is cancelled before anything is sent; nil when it created
	// the target.
	Prior *Target `json:"prior,omitempty"`
}

// Intent is a durable reservation, written before any native send.
type Intent struct {
	ID       string          `json:"id"`
	Kind     IntentKind      `json:"kind"`
	UID      int             `json:"uid"`
	MarkID   string          `json:"mark_id,omitempty"`
	Admitted time.Time       `json:"admitted"`
	Clusters []IntentCluster `json:"clusters,omitempty"`
	Seed     *Seed           `json:"seed,omitempty"`
	Done     bool            `json:"done,omitempty"`
}

// OpRecord binds an operator request ID to its action and snapshot hash and
// keeps its terminal outcome.
type OpRecord struct {
	RequestID   string     `json:"request_id"`
	Action      string     `json:"action"`
	SnapshotSHA string     `json:"snapshot_sha"`
	Outcome     *OpOutcome `json:"outcome,omitempty"`
	Done        bool       `json:"done,omitempty"`
}

// OpOutcome keeps only learning results, so serializing an operator reply
// cannot copy arbitrary message fields into the ledger.
type OpOutcome struct {
	Clusters []ClusterOutcome `json:"clusters,omitempty"`
	Digests  []Digest         `json:"digests,omitempty"`
	Outcome  string           `json:"outcome"`
	ExitOK   bool             `json:"exit_ok"`
}

// ClusterOutcome records the result for one cluster in an operator request.
type ClusterOutcome struct {
	ClusterID uint64 `json:"cluster_id"`
	Result    string `json:"result"`
}

// Usage is the learning state charged to one account or the operator.
type Usage struct {
	BodyBytes int64 `json:"body_bytes"`
	Aliases   int   `json:"aliases"`
}
