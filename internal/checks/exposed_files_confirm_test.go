package checks

import "testing"

// confirmExposure is the reachability gate: a classified candidate becomes a
// finding only when the local web server actually serves it as a raw download.
// This is what distinguishes a real leak from a file the server already blocks
// (the production host returns 403 for .env and wp-config.php despite the files
// existing on disk) and from a .php backup the interpreter executes.
func TestConfirmExposure(t *testing.T) {
	cases := []struct {
		name  string
		class exposedClass
		pr    probeResult
		want  bool
	}{
		// Raw served dumps/archives/config -> confirmed leak.
		{"sql dump served", classDBDump, probeResult{status: 200, contentType: "text/x-sql", reachable: true}, true},
		{"sql zip served", classDBDump, probeResult{status: 200, contentType: "application/zip", reachable: true}, true},
		{"config text served", classConfigLeak, probeResult{status: 200, contentType: "text/plain; charset=UTF-8", reachable: true}, true},
		{"source octet served", classSourceBackup, probeResult{status: 200, contentType: "application/octet-stream", reachable: true}, true},
		{"partial content", classBackupArchive, probeResult{status: 206, contentType: "application/gzip", reachable: true}, true},

		// Server already blocks it -> not a finding (the .env / wp-config case).
		{"forbidden", classDBDump, probeResult{status: 403, contentType: "text/html", reachable: true}, false},
		{"not found", classConfigLeak, probeResult{status: 404, contentType: "text/html", reachable: true}, false},
		{"redirect to https/login", classDBDump, probeResult{status: 301, contentType: "text/html", reachable: true}, false},

		// HTML body on a non-executing class = executed or error/challenge page,
		// not a confirmed source leak.
		{"config executed as php", classConfigLeak, probeResult{status: 200, contentType: "text/html; charset=UTF-8", reachable: true}, false},

		// phpinfo confirmed when it renders.
		{"phpinfo renders", classPHPInfo, probeResult{status: 200, contentType: "text/html; charset=UTF-8", reachable: true}, true},
		{"phpinfo blocked", classPHPInfo, probeResult{status: 403, contentType: "text/html", reachable: true}, false},

		// Unreachable -> never confirm (fail closed, no FP).
		{"unreachable", classDBDump, probeResult{reachable: false}, false},
	}

	for _, tc := range cases {
		if got := confirmExposure(tc.class, tc.pr); got != tc.want {
			t.Errorf("%s: confirmExposure(%v, %+v) = %v, want %v", tc.name, tc.class, tc.pr, got, tc.want)
		}
	}
}

func TestBestProbeResultPrefersHTTPExposureOverHTTPSRedirect(t *testing.T) {
	got := bestProbeResult([]probeResult{
		{scheme: "https", status: 301, contentType: "text/html", reachable: true},
		{scheme: "http", status: 200, contentType: "application/zip", reachable: true},
	})
	if got.scheme != "http" || got.status != 200 {
		t.Fatalf("bestProbeResult() = %+v, want reachable HTTP download", got)
	}
}

func TestBestProbeResultPrefersRawResponseOverExecutedHTML(t *testing.T) {
	got := bestProbeResult([]probeResult{
		{scheme: "https", status: 200, contentType: "text/html", reachable: true},
		{scheme: "http", status: 206, contentType: "text/plain", reachable: true},
	})
	if got.scheme != "http" || got.status != 206 {
		t.Fatalf("bestProbeResult() = %+v, want raw HTTP response", got)
	}
}

func TestPartialProbeStillConfirmsObservedExposure(t *testing.T) {
	pr := probeResult{
		scheme: "https", status: 200, contentType: "application/zip",
		reachable: true, partial: true,
	}
	if !confirmExposure(classDBDump, pr) {
		t.Fatal("observed exposure must be reported even if the other protocol failed")
	}
}
