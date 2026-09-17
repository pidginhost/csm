package health

import "time"

// WPVerificationCounts reports last observed installation coverage. Verified
// means the command completed successfully; plugin inventories can still name
// vulnerable versions. Modified core files have their own integrity findings.
type WPVerificationCounts struct {
	Verified     int       `json:"verified"`
	Modified     int       `json:"modified"`
	Unverified   int       `json:"unverified"`
	Unknown      int       `json:"unknown"`
	NotWordPress int       `json:"not_wordpress"`
	LastAttempt  time.Time `json:"last_attempt,omitzero"`
	Error        string    `json:"error,omitempty"`
}

// WordPressVerificationProvider is optional for providers predating coverage
// reporting. Absence must not be represented as a successful verification.
type WordPressVerificationProvider interface {
	WordPressVerification() map[string]WPVerificationCounts
}
