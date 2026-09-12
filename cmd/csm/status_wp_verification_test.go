package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/health"
)

func TestStatusDisplaysWordPressVerificationCoverage(t *testing.T) {
	snap := &health.Snapshot{WordPressVerification: map[string]health.WPVerificationCounts{"core": {Verified: 3, Unverified: 2}, "plugins": {Verified: 4, Unknown: 1}}}
	out := captureStdout(t, func() { printStatusHuman(control.StatusResult{Snapshot: snap}) })
	if !strings.Contains(out, "core: verified=3") || !strings.Contains(out, "unverified=2") || !strings.Contains(out, "plugins: verified=4") || !strings.Contains(out, "unknown=1") {
		t.Fatalf("status omits verification coverage: %s", out)
	}
	var buf bytes.Buffer
	writeStatusJSON(&buf, snap, "running")
	var body map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["wordpress_verification"]; !ok {
		t.Fatal("JSON status omits verification coverage")
	}
}
