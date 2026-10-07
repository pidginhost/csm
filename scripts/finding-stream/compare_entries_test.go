package main

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
)

// Spray blocks reach admission through their own entries: the incident
// spray block of one address through incident_spray, the mail spray
// subnet block through mail_subnet. Their coalesced and rootless policy
// decisions explain them; the scan entry does not.
func TestCompareMatchesSprayBlocksThroughTheirEntries(t *testing.T) {
	spray := "fid-" + strings.Repeat("1", 32)
	subnet := "fid-" + strings.Repeat("2", 32)
	restored := "fid-" + strings.Repeat("3", 32)
	findings := map[string]string{spray: "pam_bruteforce", subnet: "smtp_subnet_spray", restored: "pam_bruteforce"}
	incidentSpray := legacyBlock(spray, 10*time.Minute, "credential_spray")
	mailSubnet := legacyBlock(subnet, 20*time.Minute, "scan_subnet")
	mailSubnet.Action, mailSubnet.TargetKind, mailSubnet.TargetPrefix = "block_subnet", "cidr", 24
	rootless := legacyBlock(restored, 30*time.Minute, "credential_spray")
	coalescedSpray := summary(time.Hour, "pam_bruteforce", "coalesced", "", 1)
	coalescedSpray.Entry = "incident_spray"
	coalescedSubnet := summary(time.Hour, "smtp_subnet_spray", "coalesced", "", 1)
	coalescedSubnet.Entry, coalescedSubnet.Action = "mail_subnet", "block_subnet"
	refused := summary(time.Hour, "unknown", "refused", "policy", 1)
	refused.Entry = "incident_spray"
	last := summary(4*time.Hour, "pam_bruteforce", "queued", "", 1)
	report, err := compareReport(findings, []anonAction{incidentSpray, mailSubnet, rootless, coalescedSpray, coalescedSubnet, refused, last})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"legacy automatic actions: 3", "matched by a coalesced admission: 2", "explained by a designed refusal: 1 (policy 1)", "unexplained: 0: pass"} {
		if !strings.Contains(report, want) {
			t.Fatalf("missing %q:\n%s", want, report)
		}
	}
	// A scan-pass finding that drove a spray block has no observation yet:
	// its attribution refusal through incident_spray is designed.
	scanned := "fid-" + strings.Repeat("5", 32)
	findings[scanned] = "ip_reputation"
	attributed := legacyBlock(scanned, 40*time.Minute, "credential_spray")
	unobserved := summary(time.Hour, "ip_reputation", "refused", "attribution", 1)
	unobserved.Entry = "incident_spray"
	report, err = compareReport(findings, []anonAction{attributed, unobserved, last})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(report, "explained by a designed refusal: 1 (attribution 1)") || !strings.Contains(report, "unexplained: 0: pass") {
		t.Fatalf("a spray block of a scan-pass finding was not explained:\n%s", report)
	}
	scanEntry := coalescedSpray
	scanEntry.Entry = "scan"
	report, err = compareReport(findings, []anonAction{incidentSpray, scanEntry, last})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(report, "unexplained: 1: FAIL") {
		t.Fatalf("a scan decision explained an incident spray block:\n%s", report)
	}
}

// A legacy scan block can land from the pending queue, after its hourly
// budget refills, until the queued retry ages out. The preview observed the
// finding when it was first selected, so that earlier step explains the
// retry; a block later than the retry age does not.
func TestCompareMatchesAPendingRetryAfterItsPreview(t *testing.T) {
	fid := "fid-" + strings.Repeat("4", 32)
	findings := map[string]string{fid: "pam_bruteforce"}
	step := admissionStep(fid, 5*time.Minute)
	last := summary(6*time.Hour, "pam_bruteforce", "queued", "", 1)
	first := summary(time.Hour, "pam_bruteforce", "queued", "", 1)
	for _, tc := range []struct {
		after time.Duration
		want  string
	}{
		{95 * time.Minute, "matched by an admission step: 1"},
		{5*time.Minute + checks.PendingRetryAge + time.Minute, "matched by an admission step: 1"},
		{5*time.Minute + checks.PendingRetryAge + time.Hour + time.Minute, "unexplained: 1: FAIL"},
	} {
		retry := legacyBlock(fid, tc.after, "scan")
		report, err := compareReport(findings, []anonAction{first, step, retry, last})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(report, tc.want) {
			t.Fatalf("retry %v after the preview: missing %q:\n%s", tc.after, tc.want, report)
		}
	}
	// Only the scan path queues retries: a derived block keeps the hour.
	incident := legacyBlock(fid, 95*time.Minute, "incident")
	report, err := compareReport(findings, []anonAction{first, step, incident, last})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(report, "unexplained: 1: FAIL") {
		t.Fatalf("an incident block borrowed the retry window:\n%s", report)
	}
}
