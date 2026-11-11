package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
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
