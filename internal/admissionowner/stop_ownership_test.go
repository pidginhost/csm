package admissionowner

import (
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

// A block left to legacy during Stop must not also survive in admission's
// queue. Work accepted before Stop still belongs to admission after restart.
func TestOwnerStopLeavesNoLegacyOwnedArrivals(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	opts := executeOptions(f, newFakeBlocks())
	o := f.start(opts)
	checks.SetResponseAdmission(o)
	t.Cleanup(func() { checks.SetResponseAdmission(nil) })
	first, err := o.Mint(sshFinding(f.host.now(), "offset=before-stop", alert.High))
	if err != nil {
		t.Fatal(err)
	}
	lateFinding := sshFinding(f.host.now(), "offset=during-stop", alert.High)
	lateFinding.SourceIP = "192.0.2.11"
	late, err := o.Mint(lateFinding)
	if err != nil {
		t.Fatal(err)
	}
	if !checks.AnswerRoot(admission.KindBlockIP, targetOf(first), first, admission.EntryIncident) {
		t.Fatal("running owner did not take the first block")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	turnDone, stopDone := make(chan error, 1), make(chan struct{})
	go func() {
		turnDone <- o.do(func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	go func() { o.Stop(); close(stopDone) }()
	<-o.summaryCtx.Done()
	if checks.AnswerRoot(admission.KindBlockIP, targetOf(late), late, admission.EntryIncident) {
		t.Error("stopping owner took a new block from legacy")
	}
	if got := o.ingress.Len(); got != 1 {
		t.Errorf("held %d arrivals, want only the block taken before Stop", got)
	}
	close(release)
	if err := <-turnDone; err != nil {
		t.Fatal(err)
	}
	<-stopDone
	restarted := f.start(opts)
	queued := queuedCandidates(t, restarted)
	if len(queued) != 1 || queued[0].Key.Target != first.Target() || len(queued[0].Roots) != 1 || queued[0].Roots[0] != first.ID() {
		t.Fatalf("queue after restart = %+v, want only the block taken before Stop", queued)
	}
}
