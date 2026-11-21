package checks

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
)

// writableLogFinding is what a forged sshd line in a syslog file produces.
func writableLogFinding(producer admission.ProducerID) alert.Finding {
	return alert.Finding{
		Severity: alert.Critical, Check: "ssh_login_unknown_ip", SourceIP: "198.51.100.7",
		Attribution: admission.AttributionPeer,
		Observation: alert.Observation{Producer: string(producer), Stream: "f:1:2", Cursor: "0:0123456789abcdef", ObservedAt: time.Now()},
	}
}

// A syslog file any local user can write is not evidence of who connected:
// its findings alert, and neither admission nor the older path blocks them.
func TestWritableLogFindingNeverBlocks(t *testing.T) {
	for _, p := range []admission.ProducerID{ProducerSSHLog, ProducerSSHLoginScan, ProducerMailLog, ProducerFTPLog, ProducerFTPScan} {
		if !ProducerWritableLog(p) {
			t.Errorf("%s reads a syslog file a local user can write", p)
		}
	}
	for _, p := range []admission.ProducerID{ProducerSSHJournal, ProducerMailJournal, ProducerFTPJournal, ProducerPAMSocket,
		ProducerEximLog, ProducerStalwartLog, ProducerAccessLog, ProducerCpanelAccessLog} {
		if ProducerWritableLog(p) {
			t.Errorf("%s reads lines only a service writes", p)
		}
	}
	f := writableLogFinding(ProducerSSHLog)
	_, _, err := AdmissionEvidence(f)
	if admission.CauseOf(err) != admission.CauseWritableLog {
		t.Fatalf("AdmissionEvidence = %v, want a writable_log refusal", err)
	}
	if !taken(true, admission.KindBlockIP, err, nil) {
		t.Fatal("a writable_log refusal left the block to the older path")
	}
	if blockableFinding(f, true) {
		t.Fatal("the older path would block an address read from a writable log")
	}
	trusted := writableLogFinding(ProducerSSHJournal)
	if _, _, err := AdmissionEvidence(trusted); err != nil {
		t.Fatalf("a journal entry sshd wrote = %v, want evidence", err)
	}
	if !blockableFinding(trusted, true) {
		t.Fatal("a journal entry sshd wrote is not blockable")
	}
}

func TestWritableLogCauseVocabulary(t *testing.T) {
	if admission.CauseWritableLog != 8 || admission.CauseWritableLog.String() != "writable_log" || !admission.CauseWritableLog.Valid() {
		t.Fatalf("writable_log cause = %d %q", admission.CauseWritableLog, admission.CauseWritableLog)
	}
}

// Derived paths keep the refusal whatever lifetime they ask for, as they
// keep a forged_client one.
func TestWritableLogRootIsFinalOnDerivedPaths(t *testing.T) {
	for _, ttl := range []time.Duration{0, time.Hour, 7 * 24 * time.Hour} {
		t.Run(ttl.String(), func(t *testing.T) {
			cfg := pendingTestConfig(t)
			cfg.AutoResponse.BlockExpiry = "1h"
			blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
			applyBlockTestSetup(t, blocker)
			a := withAdmission(t)
			a.executes = true
			res, err := ApplyBlock(cfg, ApplyBlockRequest{
				IP: "198.51.100.7", TTL: ttl, Source: BlockSourceIncident, Entry: admission.EntryIncident,
				RootFinding: writableLogFinding(ProducerSSHLog),
				RootErr:     attributionRefusal(admission.CauseWritableLog),
			})
			if !errors.Is(err, ErrBlockTakenByAdmission) || res.Outcome != firewall.BlockOutcomeNoop || len(blocker.calls) != 0 {
				t.Fatalf("writable root: result %+v, err %v, calls %+v; want no block", res, err, blocker.calls)
			}
			if len(a.refused) != 1 || len(a.responses()) != 0 {
				t.Fatalf("refusals %v, responses %v; want one refusal", a.refused, a.responses())
			}
		})
	}
}

// While admission does not apply blocks, an engine outage or a held policy,
// the older path still refuses a root read from a writable log.
func TestWritableLogRootNeverBlocksWithoutAdmission(t *testing.T) {
	cfg := pendingTestConfig(t)
	blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
	applyBlockTestSetup(t, blocker)
	a := withAdmission(t)
	a.executes = false
	res, err := ApplyBlock(cfg, ApplyBlockRequest{
		IP: "198.51.100.7", TTL: time.Hour, Source: BlockSourceIncident, Entry: admission.EntryIncident,
		RootFinding: writableLogFinding(ProducerMailLog),
		RootErr:     attributionRefusal(admission.CauseWritableLog),
	})
	if err == nil || !errors.Is(err, firewall.ErrIPProtected) || res.Outcome != firewall.BlockOutcomeNoop || len(blocker.calls) != 0 {
		t.Fatalf("legacy writable root: result %+v, err %v, calls %+v; want a refusal and no block", res, err, blocker.calls)
	}
}
