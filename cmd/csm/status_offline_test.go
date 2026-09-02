package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/pidginhost/csm/internal/health"
)

// status --json printed an offline stub and exited 0 on every control
// socket error, so a permission problem or a wedged daemon looked like a
// clean "stopped" to monitoring, and the stub carried no field that told
// it apart from a live snapshot.
func TestStatusJSONFailureOnlyStubsWhenDaemonNotRunning(t *testing.T) {
	if stub, code := statusJSONFailure(errDaemonNotRunning); !stub || code != 0 {
		t.Fatalf("not running: stub=%v code=%d, want stub with exit 0", stub, code)
	}
	if stub, code := statusJSONFailure(errors.New("dial unix /run/csm.sock: permission denied")); stub || code != 1 {
		t.Fatalf("other error: stub=%v code=%d, want no stub and exit 1", stub, code)
	}
}

func TestStatusJSONCarriesStatusField(t *testing.T) {
	var buf bytes.Buffer
	writeStatusJSON(&buf, &health.Snapshot{Version: "9.9.9"}, "offline")
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if m["status"] != "offline" {
		t.Fatalf("status = %v, want offline", m["status"])
	}
	if m["version"] != "9.9.9" {
		t.Fatalf("snapshot fields not flattened: %v", m)
	}
}

func TestStatusJSONHandlesNilSnapshot(t *testing.T) {
	var buf bytes.Buffer
	writeStatusJSON(&buf, nil, "offline")
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if len(m) != 1 || m["status"] != "offline" {
		t.Fatalf("nil snapshot JSON = %v, want only offline status", m)
	}
}
