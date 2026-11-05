//go:build linux

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/emailav"
	emime "github.com/pidginhost/csm/internal/mime"
)

func init() {
	linuxIdentityCases = append(linuxIdentityCases,
		identityCase{name: "email_av_degraded", build: func(t *testing.T) (alert.Finding, alert.Finding) {
			return enginesDownDegraded(t, "tempfail", "1aBcDe-000001-XX"), enginesDownDegraded(t, "tempfail", "1aBcDe-000002-XX")
		}},
		identityCase{name: "email_av_degraded another AV condition", distinct: true, build: func(t *testing.T) (alert.Finding, alert.Finding) {
			return enginesDownDegraded(t, "tempfail", "1aBcDe-000001-XX"), partialExtractionDegraded(t, "tempfail", "1aBcDe-000001-XX")
		}},
		identityCase{name: "email_av_degraded another outcome", distinct: true, build: func(t *testing.T) (alert.Finding, alert.Finding) {
			return enginesDownDegraded(t, "tempfail", "1aBcDe-000001-XX"), enginesDownDegraded(t, "open", "1aBcDe-000001-XX")
		}},
		// The production emitter, not a copy of its shape, must carry the key.
		identityCase{name: "self_deleting_dropper_realtime wiring", build: func(t *testing.T) (alert.Finding, alert.Finding) {
			first := identityCandidate("/home/alice/public_html/x.php", 1621, 3*time.Second, "pid=4242 cmd=php-fpm uid=1001")
			second := identityCandidate("/home/alice/public_html/x.php", 2048, 7*time.Second, "pid=5353 cmd=php-fpm uid=1001")
			return wiredDropperFinding(t, soloDropper(first, dropperSuspect)), wiredDropperFinding(t, soloDropper(second, dropperSuspect))
		}},
	)
}

// wiredDropperFinding is what the detector built by initDropperDetector sends
// to the alert channel. Each call uses its own monitor so the 30s path
// cooldown does not drop the second report.
func wiredDropperFinding(t *testing.T, f dropperFinding) alert.Finding {
	t.Helper()
	cfg := &config.Config{}
	cfg.Thresholds.DropperDetection = true
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: cfg, alertCh: ch}
	fm.initDropperDetector(cfg)
	fm.dropper.emitFinding(f)
	return onlyFinding(t, takeFindings(ch))
}

func enginesDownDegraded(t *testing.T, failMode, msgID string) alert.Finding {
	t.Helper()
	dir := t.TempDir()
	buildEximSpoolWithAttachment(t, dir, msgID)
	sw, ch := extractWatcher(failMode, inProcessExtractor{dir: t.TempDir()})
	sw.orchestrator = emailav.NewOrchestrator([]emailav.Scanner{noEnginesAvailableScanner{}}, 5*time.Second)
	return spoolDegraded(t, sw, ch, dir, msgID)
}

func partialExtractionDegraded(t *testing.T, failMode, msgID string) alert.Finding {
	t.Helper()
	dir := t.TempDir()
	buildMinimalEximSpool(t, dir, msgID)
	sw, ch := extractWatcher(failMode, &recordingExtractor{size: 1, extract: func(context.Context, int) (*emime.ExtractionResult, error) {
		return &emime.ExtractionResult{Partial: true, PartialReason: "archive depth limit"}, nil
	}})
	return spoolDegraded(t, sw, ch, dir, msgID)
}

func spoolDegraded(t *testing.T, sw *SpoolWatcher, ch chan alert.Finding, dir, msgID string) alert.Finding {
	t.Helper()
	captureResponses(t)
	sw.handleSpoolEvent(bodyEvent(t, dir, msgID))
	return onlyFinding(t, findingsFor(takeFindings(ch), "email_av_degraded"))
}
