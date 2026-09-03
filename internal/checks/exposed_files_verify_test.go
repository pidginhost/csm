package checks

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// stubProbe returns a canned result for every probe, recording what it was
// asked so a test can assert the dial was pinned to the vhost's serving IP.
type stubProbe struct {
	result            probeResult
	gotDomain         string
	gotHost           string
	gotPath           string
	callCount         int
	completeCallCount int
}

func (s *stubProbe) probe(_ context.Context, domain, host, urlPath string) probeResult {
	s.record(domain, host, urlPath)
	return s.result
}

func (s *stubProbe) probeComplete(_ context.Context, domain, host, urlPath string) probeResult {
	s.completeCallCount++
	s.record(domain, host, urlPath)
	return s.result
}

func (s *stubProbe) record(domain, host, urlPath string) {
	s.callCount++
	s.gotDomain, s.gotHost, s.gotPath = domain, host, urlPath
}

const verifyUserdataMap = "shop.example.com: user1==user1==main==shop.example.com==/home/user1/public_html==192.0.2.10:80==192.0.2.10:443\n"

// exposedVerifyOS serves the vhost map and reports whether the flagged file is
// still on disk.
type exposedVerifyOS struct {
	mockOS
	present       map[string]bool
	userdataMap   string
	userdataReads int
}

func (m *exposedVerifyOS) ReadFile(name string) ([]byte, error) {
	if name == userdataDomainsPath {
		m.userdataReads++
		if m.userdataMap != "" {
			return []byte(m.userdataMap), nil
		}
		return []byte(verifyUserdataMap), nil
	}
	return nil, os.ErrNotExist
}

func (m *exposedVerifyOS) Stat(name string) (os.FileInfo, error) {
	if m.present[name] {
		return fakeFileInfo{name: "backup.zip", size: 4096}, nil
	}
	return nil, os.ErrNotExist
}

func (m *exposedVerifyOS) Lstat(name string) (os.FileInfo, error) { return m.Stat(name) }

const (
	exposedVerifyPath    = "/home/user1/public_html/wp-content/ai1wm-backups/site.wpress"
	exposedVerifyMessage = "Web-exposed site backup archive reachable at https://shop.example.com/wp-content/ai1wm-backups/site.wpress"
	exposedVerifyDetails = `File: /home/user1/public_html/wp-content/ai1wm-backups/site.wpress (4096 bytes), served as "application/octet-stream". Remove it from the web root or deny HTTP access.`
)

func withExposedVerifyEnv(t *testing.T, pr probeResult, filePresent bool) *stubProbe {
	t.Helper()

	prevOS, prevProbe := osFS, webProber
	t.Cleanup(func() { osFS, webProber = prevOS, prevProbe })

	SetOS(&exposedVerifyOS{present: map[string]bool{exposedVerifyPath: filePresent}})
	stub := &stubProbe{result: pr}
	SetWebProbe(stub)
	return stub
}

func TestExposedFileChecksAreVerifiable(t *testing.T) {
	for _, check := range []string{
		"web_exposed_backup_archive", "web_exposed_config_leak", "web_exposed_db_dump",
		"web_exposed_source_backup", "web_exposed_phpinfo", "web_exposed_sample_sql",
		"web_exposed_repo_metadata",
	} {
		if !CanVerify(check) {
			t.Errorf("%s has no verifier, so a remediated exposure can never clear", check)
		}
	}
}

func TestVerifyExposedFileResolvesWhenTheServerNowBlocksIt(t *testing.T) {
	stub := withExposedVerifyEnv(t, probeResult{status: 403, reachable: true, scheme: "https"}, true)

	got := VerifyFinding("web_exposed_backup_archive", exposedVerifyMessage, exposedVerifyDetails, exposedVerifyPath)
	if !got.Checked || !got.Resolved {
		t.Fatalf("a 403 means the exposure is closed, want checked+resolved, got %+v", got)
	}
	if stub.callCount == 0 {
		t.Fatal("verifier never probed the URL")
	}
	if stub.completeCallCount != 1 {
		t.Fatalf("verifier used %d complete probes, want 1", stub.completeCallCount)
	}
	// Public DNS may now point at another provider, so only the vhost's local
	// serving address says what this origin serves.
	if stub.gotHost != "192.0.2.10" {
		t.Fatalf("probe must dial the vhost serving IP, got %q", stub.gotHost)
	}
	if stub.gotDomain != "shop.example.com" {
		t.Fatalf("probe must present the vhost domain, got %q", stub.gotDomain)
	}
	if stub.gotPath != "/wp-content/ai1wm-backups/site.wpress" {
		t.Fatalf("probe must request the exposed path, got %q", stub.gotPath)
	}
}

func TestVerifyExposedFileStaysOpenWhileStillDownloadable(t *testing.T) {
	withExposedVerifyEnv(t, probeResult{status: 200, contentType: "application/octet-stream", reachable: true, scheme: "https"}, true)

	got := VerifyFinding("web_exposed_backup_archive", exposedVerifyMessage, exposedVerifyDetails, exposedVerifyPath)
	if got.Resolved {
		t.Fatalf("a downloadable archive is still exposed, must not resolve: %+v", got)
	}
	if !got.Checked {
		t.Fatalf("the re-check ran, so it must report as checked: %+v", got)
	}
}

func TestVerifyExposedFileResolvesWhenACompleteProbeConfirmsTheFileIsGone(t *testing.T) {
	stub := withExposedVerifyEnv(t, probeResult{status: 404, reachable: true, scheme: "https"}, false)

	got := VerifyFinding("web_exposed_backup_archive", exposedVerifyMessage, exposedVerifyDetails, exposedVerifyPath)
	if !got.Checked || !got.Resolved {
		t.Fatalf("a complete 404 for the deleted file must resolve, got %+v", got)
	}
	if stub.completeCallCount != 1 {
		t.Fatalf("a missing local file still requires one complete pinned probe, got %d", stub.completeCallCount)
	}
}

// Fail closed: an unreachable web server proves nothing. Clearing on a failed
// probe would let a web server outage silently purge real exposures.
func TestVerifyExposedFileDoesNotResolveOnAnUnreachableProbe(t *testing.T) {
	withExposedVerifyEnv(t, probeResult{reachable: false}, false)

	got := VerifyFinding("web_exposed_backup_archive", exposedVerifyMessage, exposedVerifyDetails, exposedVerifyPath)
	if got.Resolved {
		t.Fatalf("an unreachable probe must never clear a finding: %+v", got)
	}
	if got.Checked {
		t.Fatalf("an unreachable probe is not a completed check: %+v", got)
	}
}

// A partial probe (one scheme unreachable) is the same uncertainty.
func TestVerifyExposedFileDoesNotResolveOnAPartialProbe(t *testing.T) {
	withExposedVerifyEnv(t, probeResult{status: 403, reachable: true, partial: true}, false)

	got := VerifyFinding("web_exposed_backup_archive", exposedVerifyMessage, exposedVerifyDetails, exposedVerifyPath)
	if got.Checked || got.Resolved {
		t.Fatalf("a missing file plus a partial probe must remain unchecked and open: %+v", got)
	}
}

// Raw-leak classes are confirmed only by a non-HTML response. An HTML 200 is
// the server executing something or serving an error page, which is not a leak
// -- the same rule detection uses, so verification cannot disagree with it.
func TestVerifyExposedFileResolvesWhenTheServerNowReturnsHTML(t *testing.T) {
	withExposedVerifyEnv(t, probeResult{status: 200, contentType: "text/html; charset=utf-8", reachable: true}, true)

	got := VerifyFinding("web_exposed_backup_archive", exposedVerifyMessage, exposedVerifyDetails, exposedVerifyPath)
	if !got.Checked || !got.Resolved {
		t.Fatalf("an HTML response is not a confirmed raw leak, want resolved, got %+v", got)
	}
}

// phpinfo detection uses the response body after the headers gate. Verification
// must repeat that stage rather than treating every HTML 200 as a live dump.
func TestVerifyExposedPHPInfoResolvesWhenOnlyAStubRemains(t *testing.T) {
	withExposedVerifyEnv(t, probeResult{status: 200, contentType: "text/html", reachable: true, scheme: "https"}, true)
	prevFetch := fetchPHPInfoBody
	fetchPHPInfoBody = func(context.Context, string, string, string, string) ([]byte, bool) {
		return []byte("stub"), true
	}
	t.Cleanup(func() { fetchPHPInfoBody = prevFetch })

	msg := "Web-exposed phpinfo diagnostic reachable at https://shop.example.com/wp-content/ai1wm-backups/site.wpress"
	got := VerifyFinding("web_exposed_phpinfo", msg, exposedVerifyDetails, exposedVerifyPath)
	if !got.Checked || !got.Resolved {
		t.Fatalf("an HTML stub is not confirmed phpinfo output, want resolved: %+v", got)
	}
}

func TestVerifyExposedPHPInfoStaysOpenForConfirmedOutput(t *testing.T) {
	withExposedVerifyEnv(t, probeResult{status: 200, contentType: "text/html", reachable: true, scheme: "https"}, true)
	prevFetch := fetchPHPInfoBody
	body := append([]byte("PHP Version 8.3"), make([]byte, phpinfoMinBodyBytes)...)
	fetchPHPInfoBody = func(context.Context, string, string, string, string) ([]byte, bool) {
		return body, true
	}
	t.Cleanup(func() { fetchPHPInfoBody = prevFetch })

	msg := "Web-exposed phpinfo diagnostic reachable at https://shop.example.com/wp-content/ai1wm-backups/site.wpress"
	got := VerifyFinding("web_exposed_phpinfo", msg, exposedVerifyDetails, exposedVerifyPath)
	if !got.Checked || got.Resolved {
		t.Fatalf("confirmed phpinfo output must stay open: %+v", got)
	}
}

func TestVerifyExposedPHPInfoDoesNotResolveAfterIncompleteBodyChecks(t *testing.T) {
	withExposedVerifyEnv(t, probeResult{status: 200, contentType: "text/html", reachable: true, scheme: "https"}, true)
	prevFetch := fetchPHPInfoBody
	fetchPHPInfoBody = func(context.Context, string, string, string, string) ([]byte, bool) {
		return nil, false
	}
	t.Cleanup(func() { fetchPHPInfoBody = prevFetch })

	msg := "Web-exposed phpinfo diagnostic reachable at https://shop.example.com/wp-content/ai1wm-backups/site.wpress"
	got := VerifyFinding("web_exposed_phpinfo", msg, exposedVerifyDetails, exposedVerifyPath)
	if got.Checked || got.Resolved {
		t.Fatalf("incomplete phpinfo body checks must fail closed: %+v", got)
	}
}

// A domain that has left this server has no vhost row, so there is no serving
// IP to pin to. Probing it would reach whoever owns the DNS now; that answer
// says nothing about this host, so the finding must not be touched.
func TestVerifyExposedFileDoesNotResolveForAnUnknownDomain(t *testing.T) {
	stub := withExposedVerifyEnv(t, probeResult{status: 200, contentType: "text/html", reachable: true}, false)

	msg := "Web-exposed site backup archive reachable at https://moved-away.example.net/wp-content/ai1wm-backups/site.wpress"
	got := VerifyFinding("web_exposed_backup_archive", msg, exposedVerifyDetails, exposedVerifyPath)
	if got.Resolved {
		t.Fatalf("a domain this server does not serve must not clear a finding: %+v", got)
	}
	if stub.callCount != 0 {
		t.Fatal("no probe may be issued for a domain with no local vhost")
	}
	if !strings.Contains(got.Detail, "no longer served") && !strings.Contains(got.Detail, "not served") {
		t.Fatalf("detail should explain the domain is not served here, got %q", got.Detail)
	}
}

func TestVerifyExposedFileDoesNotResolveWithIncompleteVhostMap(t *testing.T) {
	conflictingRow := strings.ReplaceAll(verifyUserdataMap, "192.0.2.10", "198.51.100.20")
	for _, tc := range []struct {
		name string
		data string
	}{
		{name: "malformed row", data: verifyUserdataMap + "malformed row\n"},
		{name: "conflicting duplicate", data: verifyUserdataMap + conflictingRow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prevOS, prevProbe := osFS, webProber
			fakeOS := &exposedVerifyOS{userdataMap: tc.data}
			stub := &stubProbe{result: probeResult{status: 403, reachable: true, scheme: "https"}}
			SetOS(fakeOS)
			SetWebProbe(stub)
			t.Cleanup(func() { osFS, webProber = prevOS, prevProbe })

			got := VerifyFinding("web_exposed_backup_archive", exposedVerifyMessage, exposedVerifyDetails, exposedVerifyPath)
			if got.Checked || got.Resolved {
				t.Fatalf("an incomplete vhost map must leave the finding unchecked and open: %+v", got)
			}
			if stub.callCount != 0 {
				t.Fatal("an incomplete vhost map must not select a possibly stale serving address")
			}
		})
	}
}

func TestVerifyExposedFileDoesNotTrustOperatorFacingPathText(t *testing.T) {
	stub := withExposedVerifyEnv(t, probeResult{status: 403, reachable: true, scheme: "https"}, false)
	details := `File: /home/user1/public_html/backups/site (old)/release.wpress (4096 bytes), served as "application/octet-stream".`

	got := VerifyFinding("web_exposed_backup_archive", exposedVerifyMessage, details)
	if !got.Checked || !got.Resolved {
		t.Fatalf("a complete blocked probe must resolve independently of ambiguous detail text: %+v", got)
	}
	if stub.completeCallCount != 1 {
		t.Fatalf("operator-facing path text bypassed the required pinned probe: calls=%d", stub.completeCallCount)
	}
}

// The automatic sweep is what actually drains a stale queue; the web UI button
// only re-checks one finding at a time. An exposure the virtual patch has
// already denied must clear without an operator clicking anything.
func TestReverifySweepClearsAnExposureTheServerNowBlocks(t *testing.T) {
	withExposedVerifyEnv(t, probeResult{status: 403, reachable: true, scheme: "https"}, true)

	blocked := alert.Finding{
		Check:    "web_exposed_backup_archive",
		Message:  exposedVerifyMessage,
		Details:  exposedVerifyDetails,
		FilePath: exposedVerifyPath,
		Severity: alert.Critical,
	}
	store := &fakeFindingStore{findings: []alert.Finding{blocked}, dismissed: map[string]bool{}}

	got := ReverifyStaleFindings(store)
	if len(got) != 1 {
		t.Fatalf("sweep must dismiss the blocked exposure, got %d dismissals", len(got))
	}
	if !store.dismissed[blocked.Key()] {
		t.Fatal("sweep did not dismiss the finding in the store")
	}
}

func TestReverifySweepKeepsAnExposureStillDownloadable(t *testing.T) {
	withExposedVerifyEnv(t, probeResult{status: 200, contentType: "application/zip", reachable: true}, true)

	live := alert.Finding{
		Check:    "web_exposed_backup_archive",
		Message:  exposedVerifyMessage,
		Details:  exposedVerifyDetails,
		FilePath: exposedVerifyPath,
		Severity: alert.Critical,
	}
	store := &fakeFindingStore{findings: []alert.Finding{live}, dismissed: map[string]bool{}}

	if got := ReverifyStaleFindings(store); len(got) != 0 {
		t.Fatalf("a downloadable archive must stay open, got %+v", got)
	}
	if store.dismissed[live.Key()] {
		t.Fatal("sweep dismissed a live exposure")
	}
}

func TestReverifySweepReadsTheVhostMapOnce(t *testing.T) {
	prevOS, prevProbe := osFS, webProber
	fakeOS := &exposedVerifyOS{present: map[string]bool{exposedVerifyPath: true}}
	stub := &stubProbe{result: probeResult{status: 403, reachable: true, scheme: "https"}}
	SetOS(fakeOS)
	SetWebProbe(stub)
	t.Cleanup(func() { osFS, webProber = prevOS, prevProbe })

	findings := []alert.Finding{
		{Check: "web_exposed_backup_archive", Message: exposedVerifyMessage, Details: exposedVerifyDetails, FilePath: exposedVerifyPath},
		{Check: "web_exposed_source_backup", Message: exposedVerifyMessage, Details: exposedVerifyDetails, FilePath: exposedVerifyPath},
	}
	store := &fakeFindingStore{findings: findings, dismissed: map[string]bool{}}
	if got := ReverifyStaleFindings(store); len(got) != len(findings) {
		t.Fatalf("complete blocked probes should dismiss both findings, got %+v", got)
	}
	if fakeOS.userdataReads != 1 {
		t.Fatalf("sweep read %s %d times, want 1", userdataDomainsPath, fakeOS.userdataReads)
	}
	_ = ReverifyStaleFindings(store)
	if fakeOS.userdataReads != 2 {
		t.Fatalf("a later sweep reused stale vhost rows: total reads=%d, want 2", fakeOS.userdataReads)
	}
}

func TestReverifySweepStopsBeforeWorkWhenContextIsCanceled(t *testing.T) {
	prevOS, prevProbe := osFS, webProber
	fakeOS := &exposedVerifyOS{present: map[string]bool{exposedVerifyPath: true}}
	stub := &stubProbe{result: probeResult{status: 403, reachable: true}}
	SetOS(fakeOS)
	SetWebProbe(stub)
	t.Cleanup(func() { osFS, webProber = prevOS, prevProbe })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := &fakeFindingStore{
		findings: []alert.Finding{{
			Check: "web_exposed_backup_archive", Message: exposedVerifyMessage,
			Details: exposedVerifyDetails, FilePath: exposedVerifyPath,
		}},
		dismissed: map[string]bool{},
	}
	got, complete := ReverifyStaleFindingsContext(ctx, store)
	if len(got) != 0 {
		t.Fatalf("canceled sweep dismissed findings: %+v", got)
	}
	if complete {
		t.Fatal("canceled sweep reported complete, so its version marker could suppress the retry")
	}
	if store.latestCalls != 0 || fakeOS.userdataReads != 0 || stub.callCount != 0 {
		t.Fatalf("canceled sweep did work: finding reads=%d vhost reads=%d probes=%d",
			store.latestCalls, fakeOS.userdataReads, stub.callCount)
	}
}

func TestAutomaticSweepAllowlistExcludesOtherRegisteredVerifiers(t *testing.T) {
	for _, check := range []string{
		"webshell", "htaccess_injection", "email_phishing_content",
		"suspicious_crontab", "outdated_plugins", "uid0_account",
		"db_options_injection",
	} {
		if !CanVerify(check) {
			t.Fatalf("test precondition: %s must have an operator verifier", check)
		}
		if autoReverifiable(check) {
			t.Errorf("operator-driven verifier %s became auto-dismissible", check)
		}
	}
}

func TestCompleteWebProbeAttemptsBothSchemesBeforeReturningNegative(t *testing.T) {
	var schemes []string
	probeOne := func(_ context.Context, scheme, _, _, _ string) (probeResult, bool) {
		schemes = append(schemes, scheme)
		if scheme == "https" {
			return probeResult{scheme: scheme, status: 403, reachable: true}, true
		}
		return probeResult{}, false
	}

	got := probeLocalSchemes(context.Background(), "shop.example.com", "192.0.2.10", "/backup.zip", false, probeOne)
	if len(schemes) != 2 || schemes[0] != "https" || schemes[1] != "http" {
		t.Fatalf("complete probe attempted schemes %v, want [https http]", schemes)
	}
	if !got.partial {
		t.Fatalf("one silent scheme must mark the probe partial: %+v", got)
	}
}
