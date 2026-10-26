package firewall

import (
	"encoding/json"
	"testing"
)

func TestAutomaticStampPortableCodec(t *testing.T) {
	original := FirewallState{Blocked: []BlockedEntry{{IP: "192.0.2.90", Automatic: true}}}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var restored FirewallState
	if err = json.Unmarshal(raw, &restored); err != nil || len(restored.Blocked) != 1 || !restored.Blocked[0].Automatic {
		t.Fatalf("stamp lost: %+v %v", restored, err)
	}
}
