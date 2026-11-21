package checks

import (
	"context"
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

// The registry must refuse a direct mint too, without relying on the
// finding adapter to strip a writable producer's authority.
func TestWritableLogRegistryCannotMint(t *testing.T) {
	for _, entry := range ProducerTable() {
		if !ProducerWritableLog(entry.Spec.ID) {
			continue
		}
		t.Run(string(entry.Spec.ID), func(t *testing.T) {
			reg, err := admission.NewRegistry(AdmissionPolicy)
			if err != nil {
				t.Fatal(err)
			}
			p, err := reg.Register(entry.Spec)
			if err != nil {
				t.Fatal(err)
			}
			f := writableLogFinding(entry.Spec.ID)
			target, err := AdmissionTarget(f.SourceIP, admission.Caps{})
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.Mint(admission.EvidenceInput{
				Check: entry.Spec.Checks[0], Severity: admission.SeverityCritical,
				FindingID: alert.FindingID(f), Target: target, Attribution: admission.AttributionPeer,
				Parser: entry.Parser, ObservedAt: f.Observation.ObservedAt,
				Observation: admission.ObservationRef{Stream: "file", Cursor: "1", Version: 1},
			})
			if admission.CauseOf(err) != admission.CauseKindNotAllowed {
				t.Fatalf("direct mint = %v, want attribution refusal", err)
			}
		})
	}
}

func TestWritableLogRetainedRefusalNeverBlocks(t *testing.T) {
	for _, mode := range []string{"absent", "preview", "executing"} {
		for _, entry := range []admission.Entry{admission.EntryChallengeTimeout, admission.EntryIncident, admission.EntryIncidentSpray, admission.EntryCentral} {
			for _, ttl := range []time.Duration{0, time.Hour, 7 * 24 * time.Hour} {
				t.Run(mode+"/"+entry.String()+"/"+ttl.String(), func(t *testing.T) {
					cfg := pendingTestConfig(t)
					blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
					applyBlockTestSetup(t, blocker)
					a := withAdmission(t)
					a.executes = mode == "executing"
					if mode == "absent" {
						SetResponseAdmission(nil)
					}
					res, err := ApplyBlock(cfg, ApplyBlockRequest{
						IP: "198.51.100.7", TTL: ttl, Source: BlockSourceChallenge, Entry: entry,
						RootFinding: alert.Finding{Check: "ssh_login_unknown_ip"},
						RootErr:     attributionRefusal(admission.CauseWritableLog),
					})
					if err == nil || res.Outcome != firewall.BlockOutcomeNoop || len(blocker.calls) != 0 {
						t.Fatalf("retained refusal: %+v, %v, calls %+v", res, err, blocker.calls)
					}
				})
			}
		}
	}
}

func TestWritableLogSubnetNeverBlocks(t *testing.T) {
	for _, mode := range []string{"absent", "preview", "executing"} {
		for _, source := range []string{"summary", "constituent", "journal"} {
			t.Run(mode+"/"+source, func(t *testing.T) {
				cfg := pendingTestConfig(t)
				b := withBlocker(t)
				a := withAdmission(t)
				a.executes = mode == "executing"
				if mode == "absent" {
					SetResponseAdmission(nil)
				}
				f := sprayFinding(2)
				switch source {
				case "summary":
					f.Observation.Producer = string(ProducerMailLog)
				case "constituent":
					f.SprayConstituents[0].Observation.Producer = string(ProducerMailLog)
				}
				got := AutoBlockIPs(cfg, []alert.Finding{f})
				want := 0
				if source == "journal" {
					want = 1
				}
				if len(b.blockedSubnet) != want || len(got) != want {
					t.Fatalf("subnets %v, actions %v, want %d", b.blockedSubnet, got, want)
				}
			})
		}
	}
}

func TestWritableLogScanAndSprayNeverBlock(t *testing.T) {
	for _, mode := range []string{"absent", "preview", "executing"} {
		for _, ttl := range []time.Duration{0, time.Hour} {
			t.Run(mode+"/"+ttl.String(), func(t *testing.T) {
				cfg := pendingTestConfig(t)
				cfg.Challenge.Enabled = true
				cfg.AutoResponse.BlockCpanelLogins = true
				list := &staticChallengeIPList{ips: map[string]bool{}}
				withChallengeList(t, list)
				b := withBlocker(t)
				a := withAdmission(t)
				a.executes = mode == "executing"
				if mode == "absent" {
					SetResponseAdmission(nil)
				}
				for _, entry := range ProducerTable() {
					if !ProducerWritableLog(entry.Spec.ID) {
						continue
					}
					for _, check := range entry.Spec.Checks {
						f := writableLogFinding(entry.Spec.ID)
						f.Check, f.BlockTTL = check, ttl
						challenges, blocks := ChallengeThenBlock(cfg, []alert.Finding{f})
						if len(challenges) != 0 || len(blocks) != 0 {
							t.Fatalf("%s: challenges %v blocks %v", check, challenges, blocks)
						}
					}
				}
				if len(b.calls) != 0 || len(b.blockedSubnet) != 0 || len(list.ips) != 0 || len(loadBlockState(cfg.StatePath).Pending) != 0 {
					t.Fatalf("writable scan escaped: %+v, challenges %v", b, list.ips)
				}
			})
		}
	}
}

func TestWritableLogReputationNeverBlocks(t *testing.T) {
	for _, surface := range []string{"SSH login", "mail login"} {
		for _, age := range []time.Duration{time.Minute, 48 * time.Hour} {
			t.Run(surface+"/"+age.String(), func(t *testing.T) {
				at := time.Now().Add(-age).Truncate(time.Second)
				cfg := listIPs(t, "198.51.100.7")
				cfg.MailLogs.File = "/var/log/maillog"
				line := sightingLines("198.51.100.7", at)[surface]
				sightingLogs(t, map[string]string{logPathFor[surface]: line + "\n"})
				f := reputationFindingFor(t, CheckIPReputation(context.Background(), cfg, nil), "198.51.100.7")
				_, _, err := AdmissionEvidence(f)
				if admission.CauseOf(err) != admission.CauseWritableLog {
					t.Errorf("reputation mint = %v, want writable_log", err)
				}
				if blockableFinding(f, true) {
					t.Error("legacy would block on a writable reputation sighting")
				}
			})
		}
	}
}

func TestWritableLogRootWithoutOwnerKeepsRefusal(t *testing.T) {
	withAdmission(t)
	SetResponseAdmission(nil)
	root, err := PrepareAdmissionRoot(writableLogFinding(ProducerMailLog))
	if !root.Equal(admission.Evidence{}) || admission.CauseOf(err) != admission.CauseWritableLog {
		t.Fatalf("root %v, error %v; want writable_log without an owner", root, err)
	}
}

// Derived reputation findings can also name a proxy. The writable refusal
// must win so a compacted root cannot lose the stronger source restriction.
func TestWritableLogRefusalPrecedesProxyClassification(t *testing.T) {
	withKnownProxyPrefixes(t, "198.51.100.0/24")
	f := writableLogFinding(ProducerMailLog)
	f.Check, f.Attribution = "ip_reputation", admission.AttributionDerived
	_, _, err := AdmissionEvidence(f)
	if admission.CauseOf(err) != admission.CauseWritableLog {
		t.Fatalf("writable proxy sighting: %v, want writable_log", err)
	}
}

// Stored incident evidence is verified by its producer. Evidence older than
// this release never recorded one: for a check a syslog file producer
// emits, a missing producer cannot be told apart from a forged line.
func TestUnverifiedAddress(t *testing.T) {
	for _, tc := range []struct {
		check, producer string
		want            bool
	}{
		{"ssh_login_unknown_ip", string(ProducerSSHLog), true},
		{"ssh_login_unknown_ip", "", true},
		{"ssh_login_unknown_ip", string(ProducerSSHJournal), false},
		{"mail_bruteforce", "", true},
		{"smtp_bruteforce", string(ProducerEximLog), false},
		{"ftp_bruteforce", string(ProducerFTPScan), true},
		{"wp_login_bruteforce", "", false},
		{"modsec_csm_block_escalation", string(ProducerModSecLog), false},
	} {
		if got := UnverifiedAddress(tc.check, tc.producer); got != tc.want {
			t.Errorf("UnverifiedAddress(%q, %q) = %v, want %v", tc.check, tc.producer, got, tc.want)
		}
	}
}
