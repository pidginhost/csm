package firewall

import (
	"testing"
	"time"
)

func TestRetiredActionStateRefusesUntimedMembers(t *testing.T) {
	at := time.Now().UTC().Round(0)
	for _, mode := range []string{"unchanged permanent", "missing target", "permanent request", "not unknown", "zero instant"} {
		t.Run(mode, func(t *testing.T) {
			a := retireFixture(at)
			instant := at
			switch mode {
			case "unchanged permanent":
				row := a.After.Blocked[1]
				row.ExpiresAt = time.Time{}
				a.After.Blocked[1] = row
				a.Before.Blocked = append(a.Before.Blocked, row)
			case "missing target":
				a.Members[0].Request.Target = "203.0.113.99"
			case "permanent request":
				a.Members[0].Request.TTL = 0
			case "not unknown":
				a.Phase = "verified"
			case "zero instant":
				instant = time.Time{}
			}
			if _, ok := RetiredActionState(a, instant); ok {
				t.Fatal("ineligible checkpoint accepted")
			}
		})
	}
}
