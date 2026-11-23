package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"golang.org/x/sys/unix"
)

func exfilFinding(t *testing.T, mtime time.Time) alert.Finding {
	t.Helper()
	path := filepath.Join(t.TempDir(), "roundcube.sieve")
	if err := os.WriteFile(path, []byte(`if true { redirect "x@freemail.example"; }`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	return alert.Finding{
		Severity: alert.Critical, Check: "email_filter_exfil",
		Message:  "real@victim.example: filter redirects every message to an external address",
		Details:  "Mailbox: real@victim.example\nDomain: victim.example\nFile: " + path + "\nDestination: x@freemail.example\nfilter redirects every message",
		FilePath: path, Mailbox: "real@victim.example", Domain: "victim.example", Timestamp: time.Now(),
	}
}

// A redirect planted three months before the reporting incident counts
// toward the mailbox's evidence, not only its own finding.
func TestMailFilterRedirectIsEvidence(t *testing.T) {
	db, _ := evidenceCase(t)
	created := time.Now().Add(-90 * 24 * time.Hour).Truncate(time.Second)
	f := exfilFinding(t, created)

	if got := mailFilterEvidence(eximAutoHoldConfig(), []alert.Finding{f, {Check: "email_filter_forwarder", Mailbox: "real@victim.example"}}); len(got) != 0 {
		t.Fatalf("a redirect alone reported %+v", got)
	}
	s, ok := ledgerSignal(t, db, "real@victim.example", signalRedirect, "x@freemail.example")
	if !ok || !s.First.Equal(created) || !strings.Contains(s.Detail, f.FilePath) || !strings.Contains(s.Detail, "x@freemail.example") {
		t.Fatalf("redirect evidence = %+v (found %v), want the script, its target and its file time", s, ok)
	}

	// Every audit re-reports the redirect, which keeps the evidence alive.
	mailFilterEvidence(eximAutoHoldConfig(), []alert.Finding{f})
	if s, _ = ledgerSignal(t, db, "real@victim.example", signalRedirect, "x@freemail.example"); s.Count != 2 {
		t.Fatalf("count = %d, want 2", s.Count)
	}
}

func TestMailFilterRedirectNamedInIncident(t *testing.T) {
	_, calls := evidenceCase(t)
	cfg := eximAutoHoldConfig()
	f := exfilFinding(t, time.Now().Add(-time.Hour))
	mailFilterEvidence(cfg, []alert.Finding{f})
	incident := onlyIncident(t, observeMailboxSignal(cfg, "real@victim.example", newCountry("DE", time.Now())))
	if !strings.Contains(incident.Details, f.FilePath) || !strings.Contains(incident.Details, "x@freemail.example") {
		t.Fatalf("incident details = %s", incident.Details)
	}
	if _, err := os.Stat(f.FilePath); err != nil {
		t.Fatalf("the redirect script must stay as evidence: %v", err)
	}
	if len(*calls) != 2 {
		t.Fatalf("uapi calls = %v", *calls)
	}
}

// A domain-wide filter names no mailbox to suspend.
func TestMailFilterRedirectNeedsMailbox(t *testing.T) {
	db, _ := evidenceCase(t)
	f := exfilFinding(t, time.Now())
	f.Mailbox = ""
	mailFilterEvidence(eximAutoHoldConfig(), []alert.Finding{f})
	if s, ok := ledgerSignal(t, db, "real@victim.example", signalRedirect, "x@freemail.example"); ok {
		t.Fatalf("domain-wide filter recorded %+v", s)
	}
}

func TestMailFilterRedirectDatesEditsThroughActiveLink(t *testing.T) {
	db, _ := evidenceCase(t)
	edited := time.Now().Add(-time.Hour).Truncate(time.Second)
	f := exfilFinding(t, edited)
	link := filepath.Join(filepath.Dir(f.FilePath), ".dovecot.sieve")
	if err := os.Symlink(f.FilePath, link); err != nil {
		t.Fatal(err)
	}
	activated := unix.NsecToTimespec(edited.Add(-time.Hour).UnixNano())
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, link, []unix.Timespec{activated, activated}, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	f.FilePath = link
	mailFilterEvidence(eximAutoHoldConfig(), []alert.Finding{f})
	s, ok := ledgerSignal(t, db, f.Mailbox, signalRedirect, "x@freemail.example")
	if !ok || !s.First.Equal(edited) {
		t.Fatalf("redirect first seen at %s, want script edit at %s", s.First, edited)
	}
}

// A redirect already on disk when the daemon starts counts at once, even when
// the previous run had already reported it, and a second restart stays quiet.
func TestInitialScanRedirectIsEvidence(t *testing.T) {
	_, calls := evidenceCase(t)
	d := newTestDaemon(t)
	cfg := eximAutoHoldConfig()
	f := exfilFinding(t, time.Now().Add(-time.Hour))
	d.store.Update([]alert.Finding{f})
	d.store.MarkAlerted([]alert.Finding{f})
	if seen := d.store.FilterNew([]alert.Finding{f}); len(seen) != 0 {
		t.Fatalf("redirect not seen before the restart: %+v", seen)
	}
	observeMailboxSignal(cfg, "real@victim.example", newCountry("DE", time.Now()))

	fresh, _ := d.respondToInitialScan(cfg, []alert.Finding{f})
	if got := findingsOf(fresh, "email_mailbox_compromise"); len(got) != 1 || got[0].Mailbox != "real@victim.example" {
		t.Fatalf("startup findings = %+v, want one incident", fresh)
	}
	if len(*calls) != 2 {
		t.Fatalf("uapi calls = %v", *calls)
	}
	again, _ := d.respondToInitialScan(cfg, []alert.Finding{f})
	if got := findingsOf(again, "email_mailbox_compromise"); len(got) != 0 || len(*calls) != 2 {
		t.Fatalf("second restart reported %+v, calls %v", got, *calls)
	}
}

// copyForwardFinding is a forward that keeps a copy in the mailbox, with
// nothing else corroborating it: the filter audit reports it for review.
func copyForwardFinding(t *testing.T) alert.Finding {
	t.Helper()
	path := filepath.Join(t.TempDir(), "roundcube.sieve")
	if err := os.WriteFile(path, []byte(`if true { redirect :copy "x@freemail.example"; }`), 0o600); err != nil {
		t.Fatal(err)
	}
	return alert.Finding{
		Severity: alert.Warning, Check: "email_filter_exfil",
		Message:  "real@victim.example: filter copies every message to an external address",
		Details:  "Mailbox: real@victim.example\nDomain: victim.example\nFile: " + path + "\nDestination: x@freemail.example\nfilter copies every message",
		FilePath: path, Mailbox: "real@victim.example", Domain: "victim.example", Timestamp: time.Now(),
	}
}

// Forwarding mail to another address while keeping a copy is what owners do
// themselves. Alone it is not evidence: with one login from a new country it
// must not suspend the mailbox.
func TestMailFilterCopyForwardIsNotEvidence(t *testing.T) {
	_, calls := evidenceCase(t)
	cfg := eximAutoHoldConfig()
	observeMailboxSignal(cfg, "real@victim.example", newCountry("DE", time.Now().Add(-time.Hour)))
	got := mailFilterEvidence(cfg, []alert.Finding{copyForwardFinding(t)})
	if incidents := findingsOf(got, "email_mailbox_compromise"); len(incidents) != 0 || len(*calls) != 0 {
		t.Fatalf("a copy-keeping forward suspended the mailbox: %+v, uapi %v", incidents, *calls)
	}
}
