package alert

import (
	"encoding/json"
	"testing"
	"time"
)

func TestFindingFirstSeenJSON(t *testing.T) {
	for _, first := range []time.Time{{}, time.Unix(1_770_000_000, 123).UTC()} {
		in := Finding{Check: "webshell", Timestamp: time.Unix(1_770_000_100, 0).UTC(), FirstSeen: first}
		data, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatal(err)
		}
		if _, present := fields["first_seen"]; present == first.IsZero() {
			t.Errorf("FirstSeen %v: optional first_seen present=%v", first, present)
		}
		var out Finding
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatal(err)
		}
		if !out.FirstSeen.Equal(first) || !out.Timestamp.Equal(in.Timestamp) {
			t.Errorf("round trip lost observation or report time: %+v", out)
		}
	}
}
