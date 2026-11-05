//go:build linux

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
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
	)
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
