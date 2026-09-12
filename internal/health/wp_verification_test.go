package health

import (
	"encoding/json"
	"strings"
	"testing"
)

// A host that has never attempted a check must not publish a zero timestamp:
// operators and the API read last_attempt as "when CSM last tried".
func TestWPVerificationCountsOmitUnsetLastAttempt(t *testing.T) {
	data, err := json.Marshal(WPVerificationCounts{Verified: 2})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "last_attempt") {
		t.Fatalf("unset attempt time published as a real timestamp: %s", data)
	}
}
