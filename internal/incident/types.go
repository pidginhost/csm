// Package incident groups related security findings into a single
// "story" with a timeline. Original findings are not mutated or
// suppressed; the Incident is layered on top so operators read one
// escalating object instead of stitching findings together by hand.
package incident

import (
	"encoding/json"
	"fmt"
	"strings"
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

// ClosedRetention is how long resolved and dismissed incidents are kept after
// their last update. Operator applies to incidents an operator closed and to
// rows closed before close attribution existed; Auto applies to incidents the
// daemon closed on its own, which carry no operator decision worth keeping as
// long.
type ClosedRetention struct {
	Operator time.Duration
	Auto     time.Duration
}

// Expired reports whether a closed incident has outlived its retention.
// Active incidents never expire here.
func (r ClosedRetention) Expired(inc Incident, now time.Time) bool {
	if inc.Status != StatusResolved && inc.Status != StatusDismissed {
		return false
	}
	keep := r.Operator
	updated := inc.UpdatedAt
	if strings.HasPrefix(inc.ClosedBy, closedByAutoPrefix) {
		keep = r.Auto
		// Older operator writers left automatic attribution on closed
		// records. Preserve those decisions during the first upgraded sweep;
		// a later automatic closure starts a new retention episode.
		for i := len(inc.Actions) - 1; i >= 0; i-- {
			action := inc.Actions[i]
			if action.Action == "incident_auto_closed" {
				break
			}
			if (action.Action == "incident_status_changed" || action.Action == "operator_block") && !action.Time.Before(inc.ClosedAt) {
				keep = r.Operator
				if action.Time.After(updated) {
					updated = action.Time
				}
			}
		}
	}
	return updated.Before(now.Add(-keep))
}

// closedByAutoPrefix marks ClosedBy values the daemon writes when it closes
// an incident itself ("auto:stale", "auto:age_cap", "auto:active_cap").
const closedByAutoPrefix = "auto:"

// Kind is the high-level taxonomy a correlator assigns at create time.
// Stable strings; downstream tooling pins on these.
type Kind string

const (
	KindWebAccountCompromise Kind = "web_account_compromise"
	// KindWebAttack is an inbound web attack: a WAF hit, scanner probe,
	// or login brute-force from a remote source, plus remote-IP
	// reputation/threat-score signals. When such a finding names a victim
	// domain or account, that is the attack target, not evidence the
	// account is compromised, so these correlate on the attacker source IP
	// and get a short attacker-grade retention. Keeping them out of
	// web_account_compromise stops defended inbound traffic from inflating
	// the account-compromise count and the 7-day review window. Genuine
	// compromise is recognised by on-disk and behavioural signals
	// (webshell, suspicious PHP, post-exploit process), not by inbound hits.
	KindWebAttack Kind = "web_attack"
	// KindMailboxBruteforce is a failed-authentication brute-force attempt
	// or pre-auth mail probe against one or more mailboxes from a remote
	// source. A failed login is an attack attempt, not a takeover, so it
	// correlates on the attacker source with short attacker-grade retention.
	// Post-authentication abuse (outbound spam, cloud relay,
	// compromised-account, suspicious geo) stays in mailbox_takeover.
	KindMailboxBruteforce  Kind = "mailbox_bruteforce"
	KindMailboxTakeover    Kind = "mailbox_takeover"
	KindPostExploitProcess Kind = "post_exploit_process"
	KindHostIntegrityRisk  Kind = "host_integrity_risk"
	// KindCredentialSpray collapses a single source IP that is brute-forcing
	// many distinct mailboxes/accounts inside the merge window into one
	// super-incident keyed on the source IP. Prevents the per-mailbox fan-out
	// that turns one attacker into thousands of mailbox_bruteforce incidents.
	KindCredentialSpray Kind = "credential_spray" // #nosec G101 -- taxonomy label, not a secret
	// KindHostTakeover is the compound escalation when more than one
	// host-privilege-escalation leg (a new uid-0 account, a planted suid
	// binary, or bad-ASN outbound connection) is seen for the same host
	// inside the merge window. It ranks above KindHostIntegrityRisk so a
	// confirmed multi-leg takeover stands out from a single host-integrity
	// finding.
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
	// ClosedAt records the latest closure or operator decision on a closed
	// incident. Reopening clears it.
	ClosedAt time.Time `json:"closed_at,omitzero"`
	// ClosedBy is "operator" for manual decisions on closed incidents and
	// "auto:<reason>" for daemon closures. Empty for active or legacy rows.
	ClosedBy string `json:"closed_by,omitempty"`
	// CompoundFlags carries sticky bits used by the timeline-aware
	// reclassifier. Once set, they survive timeline trimming so an
	// early webshell or C2 signal still drives the compound rule when
	// the matching counterpart arrives much later.
	CompoundFlags CompoundFlags `json:"compound_flags,omitzero"`
	// AutoBlock records what the automatic firewall hand-off already did for
	// this incident. The block it applies expires; without this the marker
	// saying "already blocked" did not, so an attack that outlasted its
	// expiry was never blocked again.
	AutoBlock AutoBlockState `json:"auto_block,omitzero"`
}

// AutoBlockState is the escalation ladder's memory for one incident. Count is
// how many blocks the hand-off has requested, ExpiresAt when the most recent
// one lapses, and a zero ExpiresAt with a nonzero Count means that block is
// permanent and nothing re-requests it. Reset when the incident leaves an
// active status, so a later recurrence starts from the bottom of the ladder.
type AutoBlockState struct {
	Count     int       `json:"count,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	LastAt    time.Time `json:"last_at,omitzero"`
}

// lapsed reports whether the hand-off may request another block: never
// blocked, or the last block has expired. A permanent block never lapses.
func (s AutoBlockState) lapsed(now time.Time) bool {
	if s.Count == 0 {
		return true
	}
	if s.ExpiresAt.IsZero() {
		return false
	}
	return !now.Before(s.ExpiresAt)
}

// blockTTLForAttempt escalates the hand-off: the first block uses the
// operator's configured expiry, the second a week, and any later one is
// permanent (the firewall reads a zero timeout as permanent). An attacker who
// outlasts one expiry pays more each time, while a single false positive
// still ages out on its own.
func blockTTLForAttempt(attempt int, configured time.Duration) time.Duration {
	switch {
	case attempt <= 1:
		if configured <= 0 {
			return 24 * time.Hour
		}
		return configured
	case attempt == 2:
		return 7 * 24 * time.Hour
	default:
		return 0
	}
}

// CompoundFlags records the union of compound-pattern signals an
// Incident has ever observed. Fields are sticky once true; they are
// not derived from the (possibly trimmed) timeline so reclassify is
// not silently disarmed by head+tail eviction.
type CompoundFlags struct {
	Webshell bool `json:"webshell,omitempty"`
	C2       bool `json:"c2,omitempty"`
	// UID0, SUID, and BadASNOutbound record the three host-takeover legs:
	// a new uid-0 account, a planted suid binary, and an outbound connection
	// to a bad/unexpected ASN. When any two are set on one incident the
	// reclassifier escalates to KindHostTakeover.
	UID0           bool `json:"uid0,omitempty"`
	SUID           bool `json:"suid,omitempty"`
	BadASNOutbound bool `json:"bad_asn_outbound,omitempty"`
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
	Severity  string    `json:"severity,omitempty"`
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
