package checks

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// Production motivation: cluster6 carried 243 open web_exposed_* findings, all
// Critical, while every one of them had already been blocked by CSM's own
// virtual patch -- the server answered 403. Nothing cleared them because this
// family had no verifier at all, so 57% of the account's Critical queue was
// remediated work that still read as live exposure.

// stubProbe returns a canned result for every probe, recording what it was
// asked so a test can assert the dial was pinned to the vhost's serving IP.
type stubProbe struct {
	result    probeResult
	gotDomain string
	gotHost   string
	gotPath   string
	callCount int
}

func (s *stubProbe) probe(_ context.Context, domain, host, urlPath string) probeResult {
	s.callCount++
	s.gotDomain, s.gotHost, s.gotPath = domain, host, urlPath
	return s.result
}

const verifyUserdataMap = "shop.example.com: user1==user1==main==shop.example.com==/home/user1/public_html==192.0.2.10:80==192.0.2.10:443\n"

// exposedVerifyOS serves the vhost map and reports whether the flagged file is
// still on disk.
type exposedVerifyOS struct {
	mockOS
	present map[string]bool
}

func (m *exposedVerifyOS) ReadFile(name string) ([]byte, error) {
	if name == userdataDomainsPath {
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
	// The dial must be pinned to the vhost's serving IP. Public DNS is wrong:
	// occonsultingcy.com had moved to another host, which answered 200 with its
	// own HTML and would have kept a closed finding open forever.
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

func TestVerifyExposedFileResolvesWhenTheFileIsGone(t *testing.T) {
	stub := withExposedVerifyEnv(t, probeResult{status: 200, contentType: "application/octet-stream", reachable: true}, false)

	got := VerifyFinding("web_exposed_backup_archive", exposedVerifyMessage, exposedVerifyDetails, exposedVerifyPath)
	if !got.Checked || !got.Resolved {
		t.Fatalf("a deleted file cannot be exposed, want checked+resolved, got %+v", got)
	}
	if stub.callCount != 0 {
		t.Fatal("no probe is needed once the file is gone")
	}
}

// Fail closed: an unreachable web server proves nothing. Clearing on a failed
// probe would let a web server outage silently purge real exposures.
func TestVerifyExposedFileDoesNotResolveOnAnUnreachableProbe(t *testing.T) {
	withExposedVerifyEnv(t, probeResult{reachable: false}, true)

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
	withExposedVerifyEnv(t, probeResult{status: 403, reachable: true, partial: true}, true)

	got := VerifyFinding("web_exposed_backup_archive", exposedVerifyMessage, exposedVerifyDetails, exposedVerifyPath)
	if got.Resolved {
		t.Fatalf("a partial probe must not clear a finding: %+v", got)
	}
}

// Raw-leak classes are confirmed only by a non-HTML body. An HTML 200 is the
// server executing something or serving an error page, which is not a leak --
// the same rule detection uses, so verification cannot disagree with it.
func TestVerifyExposedFileResolvesWhenTheServerNowReturnsHTML(t *testing.T) {
	withExposedVerifyEnv(t, probeResult{status: 200, contentType: "text/html; charset=utf-8", reachable: true}, true)

	got := VerifyFinding("web_exposed_backup_archive", exposedVerifyMessage, exposedVerifyDetails, exposedVerifyPath)
	if !got.Checked || !got.Resolved {
		t.Fatalf("an HTML response is not a confirmed raw leak, want resolved, got %+v", got)
	}
}

// phpinfo is confirmed by any 200, HTML included, so it must stay open here.
func TestVerifyExposedPHPInfoStaysOpenOnHTML(t *testing.T) {
	withExposedVerifyEnv(t, probeResult{status: 200, contentType: "text/html", reachable: true}, true)

	msg := "Web-exposed phpinfo diagnostic reachable at https://shop.example.com/wp-content/ai1wm-backups/site.wpress"
	got := VerifyFinding("web_exposed_phpinfo", msg, exposedVerifyDetails, exposedVerifyPath)
	if got.Resolved {
		t.Fatalf("a phpinfo page answering 200 is still exposed: %+v", got)
	}
}

// A domain that has left this server has no vhost row, so there is no serving
// IP to pin to. Probing it would reach whoever owns the DNS now; that answer
// says nothing about this host, so the finding must not be touched.
func TestVerifyExposedFileDoesNotResolveForAnUnknownDomain(t *testing.T) {
	stub := withExposedVerifyEnv(t, probeResult{status: 200, contentType: "text/html", reachable: true}, true)

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
