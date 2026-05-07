package alert

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/processctx"
)

func TestFindingOmitsProcessWhenNil(t *testing.T) {
	f := Finding{Check: "x", Message: "y", Timestamp: time.Unix(1700000000, 0).UTC()}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), `"process"`) {
		t.Errorf("expected process omitted when nil; got %s", b)
	}
}

func TestFindingIncludesProcessWhenSet(t *testing.T) {
	pc := &processctx.ProcessContext{
		PID: 1234, PPID: 1, UID: 1001, User: "alice", Account: "alice", Comm: "ncat",
	}
	f := Finding{Check: "x", Message: "y", Timestamp: time.Unix(1700000000, 0).UTC(), Process: pc}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"process":{`, `"pid":1234`, `"account":"alice"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("expected %q in %s", want, b)
		}
	}
}
