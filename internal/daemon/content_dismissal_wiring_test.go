package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func daemonContentFinding(sha string) alert.Finding {
	return alert.Finding{Check: "yara_match_scheduled", Severity: alert.Critical,
		Message:   "YARA rule match [webshell_generic]: /home/a/public_html/x.php",
		Details:   "Scheduled deep scan matched YARA rule webshell_generic",
		FilePath:  "/home/a/public_html/x.php",
		Timestamp: time.Now(), ContentSHA256: sha}
}

// dismissListed dismisses f the way the Findings page does.
func dismissListed(d *Daemon, f alert.Finding) {
	d.store.Update([]alert.Finding{f})
	d.store.SetLatestFindings([]alert.Finding{f})
	d.store.DismissFindingWithUndo(f.Key())
}

func TestDispatchBatchAlertsDismissedFileWithNewContent(t *testing.T) {
	cfg, hook := emailRepeatSetup(t)
	d := openRepeatDaemon(t, cfg)
	a := daemonContentFinding(strings.Repeat("a", 64))
	b := daemonContentFinding(strings.Repeat("b", 64))
	dismissListed(d, a)

	d.dispatchBatch([]alert.Finding{a})
	if got := hook.count("webshell_generic"); got != 0 {
		t.Fatalf("dismissed content alerted: webhooks = %d", got)
	}

	d.dispatchBatch([]alert.Finding{b})
	if got := hook.count("webshell_generic"); got != 1 {
		t.Fatalf("rewritten file: webhooks = %d, want 1", got)
	}
	if e, ok := d.store.EntryForKey(b.Key()); !ok || e.IsBaseline {
		t.Fatalf("entry = %+v, ok %v; want an active detection", e, ok)
	}

	d.dispatchBatch([]alert.Finding{b})
	if got := hook.count("webshell_generic"); got != 1 {
		t.Fatalf("repeat of the new content: webhooks = %d, want 1", got)
	}
}

func TestRespondToInitialScanAlertsDismissedFileWithNewContent(t *testing.T) {
	cfg, _ := emailRepeatSetup(t)
	d := openRepeatDaemon(t, cfg)
	b := daemonContentFinding(strings.Repeat("b", 64))
	dismissListed(d, daemonContentFinding(strings.Repeat("a", 64)))

	newFindings, _ := d.respondToInitialScan(cfg, []alert.Finding{b})

	for _, f := range newFindings {
		if f.ContentSHA256 == b.ContentSHA256 {
			return
		}
	}
	t.Fatalf("initial scan did not report the rewritten file: %+v", newFindings)
}

func TestDispatchBatchKeepsDismissalForNonContentFinding(t *testing.T) {
	cfg, hook := emailRepeatSetup(t)
	d := openRepeatDaemon(t, cfg)
	f := repeatFinding("core file changed")
	dismissListed(d, f)

	f.FilePath = "/home/example/public_html/wp-includes/other.php"
	d.dispatchBatch([]alert.Finding{f})

	if got := hook.count(f.Message); got != 0 {
		t.Fatalf("dismissed finding without content alerted: webhooks = %d", got)
	}
}

func TestContentDismissalAcrossDaemonPaths(t *testing.T) {
	for _, path := range []struct {
		name string
		run  func(*testing.T, *Daemon, *config.Config, []alert.Finding)
	}{
		{name: "dispatch", run: func(_ *testing.T, d *Daemon, _ *config.Config, findings []alert.Finding) {
			d.dispatchBatch(findings)
		}},
		{name: "initial scan", run: func(_ *testing.T, d *Daemon, cfg *config.Config, findings []alert.Finding) {
			fresh, _ := d.respondToInitialScan(cfg, findings)
			d.store.Update(findings)
			d.store.MarkAlerted(fresh)
		}},
		{name: "pending replay", run: func(t *testing.T, d *Daemon, cfg *config.Config, findings []alert.Finding) {
			d.persistPendingFindingsOnShutdown(findings)
			if err := d.store.Close(); err != nil {
				t.Fatal(err)
			}
			restarted := openRepeatDaemon(t, cfg)
			d.store = restarted.store
			d.replayPendingFindings()
		}},
	} {
		for _, evidence := range []struct {
			name    string
			content string
			carried bool
			changed bool
		}{
			{name: "unchanged", content: strings.Repeat("a", 64)},
			{name: "changed", content: strings.Repeat("b", 64), changed: true},
			{name: "unknown"},
			{name: "carried", content: strings.Repeat("b", 64), carried: true},
		} {
			t.Run(path.name+"/"+evidence.name, func(t *testing.T) {
				cfg, hook := emailRepeatSetup(t)
				d := openRepeatDaemon(t, cfg)
				calls := stubQueueCompanionSweeps(t)
				a := daemonContentFinding(strings.Repeat("a", 64))
				dismissListed(d, a)
				f := daemonContentFinding(evidence.content)
				f.ScanCarryForward = evidence.carried

				path.run(t, d, cfg, []alert.Finding{f})

				want := 0
				if evidence.changed {
					want = 1
				}
				if got := hook.count("webshell_generic"); got != want {
					t.Errorf("webhooks = %d, want %d", got, want)
				}
				if got := queuedPaths(*calls)[f.FilePath]; got != want {
					t.Errorf("response findings = %d, want %d", got, want)
				}
				if got := d.store.Acknowledged(f); got == evidence.changed {
					t.Errorf("acknowledged = %v, want %v", got, !evidence.changed)
				}
				if !evidence.changed {
					e, ok := d.store.EntryForKey(f.Key())
					if !ok || e.ContentSHA256 != a.ContentSHA256 {
						t.Fatalf("dismissal content = %q, present %v; want %q", e.ContentSHA256, ok, a.ContentSHA256)
					}
				}
				// Neither delivery nor response repeats after the first batch.
				d.dispatchBatch([]alert.Finding{f})
				if got := hook.count("webshell_generic"); got != want {
					t.Errorf("webhooks after repeat = %d, want %d", got, want)
				}
				if got := queuedPaths(*calls)[f.FilePath]; got != want {
					t.Errorf("response findings after repeat = %d, want %d", got, want)
				}
			})
		}
	}
}

func TestDispatchBatchReconcilesContentBeforeDeduplication(t *testing.T) {
	for _, first := range []struct {
		name    string
		content string
		carried bool
	}{
		{name: "unchanged", content: strings.Repeat("a", 64)},
		{name: "unknown"},
		{name: "carried", content: strings.Repeat("b", 64), carried: true},
	} {
		t.Run(first.name, func(t *testing.T) {
			cfg, hook := emailRepeatSetup(t)
			d := openRepeatDaemon(t, cfg)
			calls := stubQueueCompanionSweeps(t)
			dismissListed(d, daemonContentFinding(strings.Repeat("a", 64)))
			a := daemonContentFinding(first.content)
			a.ScanCarryForward = first.carried
			b := daemonContentFinding(strings.Repeat("b", 64))
			if a.Key() != b.Key() || a.Fingerprint() != b.Fingerprint() {
				t.Fatal("content variants must share their finding identity")
			}

			d.dispatchBatch([]alert.Finding{a, b})

			if got := hook.count("webshell_generic"); got != 1 {
				t.Errorf("changed content in duplicate: webhooks = %d, want 1", got)
			}
			if got := queuedPaths(*calls)[b.FilePath]; got != 1 {
				t.Errorf("response findings = %d, want 1", got)
			}
			if d.store.Acknowledged(b) {
				t.Fatal("changed content in duplicate is still acknowledged")
			}
		})
	}
}
