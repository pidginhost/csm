package incident

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestOperatorBlockValidatesIncidentAddress(t *testing.T) {
	for _, tc := range []struct {
		name     string
		key      *Key
		timeline []IncidentEvent
		ip       string
		valid    bool
	}{
		{"mismatch", &Key{RemoteIP: "192.0.2.10"}, nil, "192.0.2.11", false},
		{"ambiguous", &Key{Account: "alice"}, []IncidentEvent{{RemoteIP: "192.0.2.10"}, {RemoteIP: "192.0.2.11"}}, "192.0.2.10", false},
		{"truncated", &Key{Account: "alice"}, []IncidentEvent{{RemoteIP: "192.0.2.10"}, {Kind: incidentTimelineTruncatedKind}}, "192.0.2.10", false},
		{"canonical", &Key{RemoteIP: "2001:db8::1"}, nil, "2001:0db8:0:0:0:0:0:1", true},
		{"timeline", &Key{Account: "alice"}, []IncidentEvent{{RemoteIP: "192.0.2.10"}}, "192.0.2.10", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCorrelator(CorrelatorConfig{})
			c.Restore([]Incident{{ID: "inc_test", Status: StatusOpen, CorrelationKey: tc.key, Timeline: tc.timeline}})
			before, _ := c.Get("inc_test")
			err := c.RecordOperatorBlock("inc_test", tc.ip, 0)
			if (err == nil) != tc.valid {
				t.Fatalf("RecordOperatorBlock error = %v, valid = %v", err, tc.valid)
			}
			after, _ := c.Get("inc_test")
			if !tc.valid && !reflect.DeepEqual(before, after) {
				t.Fatal("unrelated block changed incident state")
			}
		})
	}
	c := NewCorrelator(CorrelatorConfig{})
	if err := c.RecordOperatorBlock("inc_missing\nforged log", "192.0.2.10", 0); !errors.Is(err, ErrIncidentNotFound) {
		t.Fatalf("unknown incident error = %v, want ErrIncidentNotFound", err)
	}
}

func TestOperatorBlockDoesNotAdvanceAnActiveRung(t *testing.T) {
	var cap blockCapture
	c, setNow := escalationCorrelator(t, &cap)
	start := time.Unix(1_700_000_000, 0)
	sprayBurst(c, start, 0)
	var id string
	for _, inc := range c.Snapshot() {
		if inc.Kind == KindCredentialSpray {
			id = inc.ID
		}
	}
	for i := 0; i < 2; i++ {
		if err := c.RecordOperatorBlock(id, "192.0.2.10", 24*time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	inc, _ := c.Get(id)
	if inc.AutoBlock.Count != 1 {
		t.Errorf("refresh consumed rungs: %+v", inc.AutoBlock)
	}
	setNow(start.Add(25 * time.Hour))
	sprayBurst(c, start.Add(25*time.Hour), 10)
	if cap.len() != 2 || cap.calls[1].TTL != 7*24*time.Hour {
		t.Fatalf("next block = %+v, want week-long second rung", cap.calls)
	}
}

func TestOperatorBlockKeepsClosedLadderReset(t *testing.T) {
	for _, status := range []Status{StatusResolved, StatusDismissed} {
		t.Run(string(status), func(t *testing.T) {
			c := NewCorrelator(CorrelatorConfig{})
			c.Restore([]Incident{{ID: "inc_closed", Status: status, CorrelationKey: &Key{RemoteIP: "192.0.2.10"}}})
			if err := c.RecordOperatorBlock("inc_closed", "192.0.2.10", 0); err != nil {
				t.Fatal(err)
			}
			inc, _ := c.Get("inc_closed")
			if inc.AutoBlock != (AutoBlockState{}) {
				t.Fatalf("closed incident acquired ladder state: %+v", inc.AutoBlock)
			}
			if !hasIncidentAction(inc.Actions, "operator_block") {
				t.Fatal("closed incident lost operator audit action")
			}
		})
	}
}
