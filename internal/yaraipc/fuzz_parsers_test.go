package yaraipc

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzDecodeScanReply(f *testing.F) {
	for _, seed := range []string{
		`{"matches":[]}`, `{"matches":[{"rule":"hit"}]}`, `null`, `{}`,
		`{"matches":null}`, `{"matches":[],"partial":true}`,
		`{"matches":[]} {"matches":[]}`, "{\"matches\":[{\"rule\":\"\xff\"}]}",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		matches, err := DecodeScanReply(payload)
		if err != nil {
			return
		}
		if !json.Valid(payload) || !utf8.Valid(payload) || matches == nil {
			t.Fatalf("accepted invalid scan result: %q", payload)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(payload, &fields); err != nil || len(fields) == 0 {
			t.Fatalf("accepted unrelated scan result: %q", payload)
		}
		for name := range fields {
			if !strings.EqualFold(name, "matches") {
				t.Fatalf("accepted unknown result field: %q", name)
			}
		}
	})
}
