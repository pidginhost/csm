package alert

// Cause names the finding a derived finding was made from: its audit
// identity and its check.
type Cause struct {
	FindingID string `json:"finding_id"`
	Check     string `json:"check"`
}

// CauseOf names f as the cause of a finding derived from it.
func CauseOf(f Finding) Cause {
	return Cause{FindingID: FindingID(f), Check: f.Check}
}
