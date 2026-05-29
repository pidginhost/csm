// Package incident groups related security findings into a single
// "story" with a timeline. Original findings are not mutated or
// suppressed; the Incident is layered on top so operators read one
// escalating object instead of stitching findings together by hand.
package incident

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// Status is the lifecycle position of an incident.
type Status string

const (
	StatusOpen      Status = "open"
	StatusContained Status = "contained"
	StatusResolved  Status = "resolved"
	StatusDismissed Status = "dismissed"
)

// Kind is the high-level taxonomy a correlator assigns at create time.
// Stable strings; downstream tooling pins on these.
type Kind string

const (
	KindWebAccountCompromise Kind = "web_account_compromise"
	KindMailboxTakeover      Kind = "mailbox_takeover"
	KindPostExploitProcess   Kind = "post_exploit_process"
	KindHostIntegrityRisk    Kind = "host_integrity_risk"
	// KindCredentialSpray collapses a single source IP that is brute-forcing
	// many distinct mailboxes/accounts inside the merge window into one
	// super-incident keyed on the source IP. Prevents the per-mailbox fan-out
	// that turns one attacker into thousands of mailbox_takeover incidents.
	KindCredentialSpray Kind = "credential_spray" // #nosec G101 -- taxonomy label, not a secret
	// KindHostTakeover is the compound escalation when more than one
	// host-privilege-escalation leg (a new uid-0 account, a planted suid
	// binary) is seen for the same host inside the merge window. It ranks
	// above KindHostIntegrityRisk so a confirmed multi-leg takeover stands
	// out from a single host-integrity finding.
	KindHostTakeover Kind = "host_takeover"
)

// Incident is the wire shape every consumer (API, control socket,
// audit propagation) sees. omitempty fields are absent from JSON when
// zero so consumers ignore optional context cleanly.
type Incident struct {
	ID             string           `json:"id"`
	Kind           Kind             `json:"kind"`
	Status         Status           `json:"status"`
	Severity       alert.Severity   `json:"severity"`
	Account        string           `json:"account,omitempty"`
	Domain         string           `json:"domain,omitempty"`
	Mailbox        string           `json:"mailbox,omitempty"`
	CorrelationKey *Key             `json:"correlation_key,omitempty"`
	Summary        string           `json:"summary,omitempty"`
	Confidence     int              `json:"confidence,omitempty"`
	Findings       []string         `json:"findings,omitempty"`
	Timeline       []IncidentEvent  `json:"timeline,omitempty"`
	Actions        []IncidentAction `json:"actions,omitempty"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
	// ClosedAt is set when an incident transitions out of Open/Contained.
	// Populated by SetStatus and CloseStale; zero for active incidents so
	// existing webhook/SIEM consumers see no diff (omitempty).
	ClosedAt time.Time `json:"closed_at,omitempty"`
	// ClosedBy attributes the close. "operator" for SetStatus calls,
	// "auto:stale" for CloseStale. Empty for active incidents.
	ClosedBy string `json:"closed_by,omitempty"`
	// CompoundFlags carries sticky bits used by the timeline-aware
	// reclassifier. Once set, they survive timeline trimming so an
	// early webshell or C2 signal still drives the compound rule when
	// the matching counterpart arrives much later.
	CompoundFlags CompoundFlags `json:"compound_flags,omitzero"`
}

// CompoundFlags records the union of compound-pattern signals an
// Incident has ever observed. Fields are sticky once true; they are
// not derived from the (possibly trimmed) timeline so reclassify is
// not silently disarmed by head+tail eviction.
type CompoundFlags struct {
	Webshell bool `json:"webshell,omitempty"`
	C2       bool `json:"c2,omitempty"`
	// UID0 and SUID record the two host-privilege-escalation legs (a new
	// uid-0 account, a planted suid binary). When both are set on one
	// incident the reclassifier escalates to KindHostTakeover. A future
	// bad_asn_outbound leg would add a third bit here once an ASN
	// classifier exists.
	UID0 bool `json:"uid0,omitempty"`
	SUID bool `json:"suid,omitempty"`
}

// MarshalJSON renders Severity as its uppercase string form
// ("HIGH", "CRITICAL", "WARNING") instead of the underlying int.
// alert.Severity is an int enum, so default marshaling would emit
// numbers; consumers (web UI, control socket, audit propagation)
// expect the same human-readable token already produced by
// audit_sink and webhook dispatch.
func (i Incident) MarshalJSON() ([]byte, error) {
	type wireIncident Incident
	return json.Marshal(struct {
		wireIncident
		Severity string `json:"severity"`
	}{
		wireIncident: wireIncident(i),
		Severity:     i.Severity.String(),
	})
}

// UnmarshalJSON decodes the wire shape produced by MarshalJSON. Severity
// is read from its string form ("WARNING"/"HIGH"/"CRITICAL") and converted
// back to alert.Severity. Unknown strings return an error so SIEM-side
// schema drift is loud, not silent.
func (i *Incident) UnmarshalJSON(data []byte) error {
	type wireIncident Incident
	aux := struct {
		*wireIncident
		Severity string `json:"severity"`
	}{wireIncident: (*wireIncident)(i)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	switch aux.Severity {
	case "":
		// allow the zero-severity case for partial decodes (tests, partial
		// JSON snippets in the API). Severity stays at zero value (Warning).
	case "WARNING":
		i.Severity = alert.Warning
	case "HIGH":
		i.Severity = alert.High
	case "CRITICAL":
		i.Severity = alert.Critical
	default:
		return fmt.Errorf("incident: unknown severity %q", aux.Severity)
	}
	return nil
}

// IncidentEvent is one entry in an incident's timeline. Built from a
// Finding when it joins the incident; carries enough context to
// render the timeline without re-reading the original record.
type IncidentEvent struct {
	Time      time.Time `json:"time"`
	Kind      string    `json:"kind"`
	Check     string    `json:"check,omitempty"`
	Message   string    `json:"message"`
	FindingID string    `json:"finding_id,omitempty"`
	PID       int       `json:"pid,omitempty"`
	UID       int       `json:"uid,omitempty"`
	Process   string    `json:"process,omitempty"`
	Path      string    `json:"path,omitempty"`
	RemoteIP  string    `json:"remote_ip,omitempty"`
}

// IncidentAction is an automated or operator action that touched the
// incident. Appended to the timeline; surfaced separately so dashboards
// can filter by what the system did vs what it observed.
type IncidentAction struct {
	Time    time.Time `json:"time"`
	Action  string    `json:"action"`
	Result  string    `json:"result"`
	Details string    `json:"details,omitempty"`
}
