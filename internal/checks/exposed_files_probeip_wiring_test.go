package checks

import (
	"context"
	"path/filepath"
	"testing"
)

// recordingProbe captures the dial host it was asked to probe with.
type recordingProbe struct {
	host   string
	calls  int
	result probeResult
}

func (r *recordingProbe) probe(_ context.Context, _ string, host, _ string) probeResult {
	r.host = host
	r.calls++
	return r.result
}

// TestScanVhostsProbesServingIP proves the regression fix: the scan dials the
// vhost's serving IP, not 127.0.0.1. A loopback probe was returning 403 on
// LiteSpeed and suppressing every real finding.
func TestScanVhostsProbesServingIP(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "softsql.sql"), "-- dump\n")

	rec := &recordingProbe{result: probeResult{status: 200, contentType: "text/x-sql", reachable: true}}
	withFakeProbe(t, rec)

	findings := scanVhostsForExposure(context.Background(), []vhost{{
		domain: "carbatteries.example", user: "u", typ: "addon",
		docroot: root, ip: "198.51.100.42",
	}}, nil)

	if rec.host != "198.51.100.42" {
		t.Fatalf("probe dialed host %q, want the vhost serving IP 198.51.100.42", rec.host)
	}
	if rec.calls != 1 {
		t.Fatalf("probe calls = %d, want one", rec.calls)
	}
	if len(findings) != 1 || findings[0].Check != "web_exposed_db_dump" {
		t.Fatalf("expected one db_dump finding, got %+v", findings)
	}
}

func TestScanVhostsWithoutServingIPIsIncompleteAndNotProbed(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "softsql.sql"), "-- dump\n")
	rec := &recordingProbe{result: probeResult{status: 200, reachable: true}}
	withFakeProbe(t, rec)
	ctx, collector := withIncompleteCheckCollector(context.Background())

	findings := scanVhostsForExposure(ctx, []vhost{{
		domain: "example.com", user: "u", typ: "main", docroot: root,
	}}, nil)

	if len(findings) != 0 || rec.calls != 0 {
		t.Fatalf("unaddressed vhost findings = %+v, probe calls = %d; want neither", findings, rec.calls)
	}
	if !collector.contains("exposed_files") {
		t.Fatal("vhost without a serving IP must preserve findings from the prior completed scan")
	}
}
