package daemon

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/queuehealth"
)

// identityCase builds two findings through a real producer. A re-report
// differs from the first only in volatile text and must keep its email
// identity; a distinct case names another condition and must not share it.
type identityCase struct {
	name     string
	build    func(t *testing.T) (alert.Finding, alert.Finding)
	distinct bool
}

// linuxIdentityCases holds the rows whose producers build only on Linux.
var linuxIdentityCases []identityCase

// Alert email and the webhook send a finding again only when Key or
// Fingerprint changes. A count, message ID or write age in either would email
// the same ongoing condition on every report.
func TestReReportKeepsEmailIdentity(t *testing.T) {
	cases := []identityCase{
		{name: "smtp_probe_abuse", build: func(t *testing.T) (alert.Finding, alert.Finding) {
			return smtpProbeAbuse(t, "203.0.113.5", 3), smtpProbeAbuse(t, "203.0.113.5", 4)
		}},
		{name: "smtp_probe_abuse another IP", distinct: true, build: func(t *testing.T) (alert.Finding, alert.Finding) {
			return smtpProbeAbuse(t, "203.0.113.5", 3), smtpProbeAbuse(t, "198.51.100.7", 3)
		}},
		{name: "self_deleting_dropper_realtime file", build: func(t *testing.T) (alert.Finding, alert.Finding) {
			first := identityCandidate("/home/alice/public_html/x.php", 1621, 3*time.Second, "pid=4242 cmd=php-fpm uid=1001")
			second := identityCandidate("/home/alice/public_html/x.php", 2048, 7*time.Second, "pid=5353 cmd=php-fpm uid=1001")
			return dropperAlertFinding(soloDropper(first, dropperSuspect)), dropperAlertFinding(soloDropper(second, dropperSuspect))
		}},
		{name: "self_deleting_dropper_realtime another path", distinct: true, build: func(t *testing.T) (alert.Finding, alert.Finding) {
			first := identityCandidate("/home/alice/public_html/x.php", 1621, 3*time.Second, "")
			second := identityCandidate("/home/alice/public_html/y.php", 1621, 3*time.Second, "")
			return dropperAlertFinding(soloDropper(first, dropperSuspect)), dropperAlertFinding(soloDropper(second, dropperSuspect))
		}},
		// A demoted report must not hide a later Critical one for the same path.
		{name: "self_deleting_dropper_realtime demoted then undemoted", distinct: true, build: func(t *testing.T) (alert.Finding, alert.Finding) {
			c := identityCandidate("/home/alice/public_html/x.php", 1621, 3*time.Second, "")
			return dropperAlertFinding(soloDropper(c, dropperDemotedTemplate)), dropperAlertFinding(soloDropper(c, dropperSuspect))
		}},
		{name: "self_deleting_dropper_realtime removed dir", build: func(t *testing.T) (alert.Finding, alert.Finding) {
			removed := func(n int) dropperFinding {
				f := dropperFinding{Docroot: "/home/alice/public_html", RemovedDir: "/home/alice/public_html/tmp-x"}
				for i := range n {
					c := identityCandidate(fmt.Sprintf("/home/alice/public_html/tmp-x/%d.php", i), int64(100*(i+1)), time.Second, "")
					f.Items = append(f.Items, dropperGone{Cand: c, Verdict: dropperDemotedDirRemoved})
				}
				return f
			}
			return dropperAlertFinding(removed(2)), dropperAlertFinding(removed(3))
		}},
		{name: "self_deleting_dropper_realtime docroot burst", build: func(t *testing.T) (alert.Finding, alert.Finding) {
			burst := func(n int) dropperFinding {
				f := dropperFinding{Aggregate: true, Docroot: "/home/alice/public_html"}
				for i := range n {
					c := identityCandidate(fmt.Sprintf("/home/alice/public_html/cache/%d.php", i), int64(100*(i+1)), time.Second, "")
					f.Items = append(f.Items, dropperGone{Cand: c, Verdict: dropperSuspect})
				}
				return f
			}
			return dropperAlertFinding(burst(dropperBurstThreshold)), dropperAlertFinding(burst(dropperBurstThreshold + 2))
		}},

		// Already stable: pins only.
		{name: "protection_queue_degraded", build: func(t *testing.T) (alert.Finding, alert.Finding) {
			return queueHealthReReports(t, "protection_queue_degraded")
		}},
		{name: "protection_queue_recovered", build: func(t *testing.T) (alert.Finding, alert.Finding) {
			return queueHealthReReports(t, "protection_queue_recovered")
		}},
		{name: "php_shield_block", build: phpShieldReReport("BLOCK_PATH")},
		{name: "php_shield_webshell", build: phpShieldReReport("BLOCK_WEBSHELL")},
		{name: "php_shield_eval", build: phpShieldReReport("EVAL_FATAL")},
	}
	for _, tc := range append(cases, linuxIdentityCases...) {
		t.Run(tc.name, func(t *testing.T) {
			first, second := tc.build(t)
			if first.Check == "" || first.Check != second.Check {
				t.Fatalf("fixture built %q and %q, want one check", first.Check, second.Check)
			}
			if tc.distinct {
				if first.Key() == second.Key() {
					t.Fatalf("distinct conditions share identity %q:\n first=%+v\nsecond=%+v", first.Key(), first, second)
				}
				return
			}
			if first.Message == second.Message && first.Details == second.Details {
				t.Fatalf("fixture does not vary between reports: %+v", first)
			}
			if first.Key() != second.Key() {
				t.Fatalf("identity changed between reports:\n first=%q\nsecond=%q", first.Key(), second.Key())
			}
			if first.Fingerprint() != second.Fingerprint() {
				t.Fatalf("fingerprint changed between reports: %q vs %q", first.Fingerprint(), second.Fingerprint())
			}
		})
	}
}

// A scanner whose connection count grows between reports is one condition:
// one webhook, not one per count.
func TestDispatchBatchVolatileReReportNotReEmailed(t *testing.T) {
	cfg, hook := emailRepeatSetup(t)
	d := openRepeatDaemon(t, cfg)

	d.dispatchBatch([]alert.Finding{smtpProbeAbuse(t, "203.0.113.5", 3)})
	d.dispatchBatch([]alert.Finding{smtpProbeAbuse(t, "203.0.113.5", 4)})

	if got := hook.count("SMTP probe abuse from 203.0.113.5"); got != 1 {
		t.Errorf("webhooks = %d, want 1", got)
	}
}

func onlyFinding(t *testing.T, findings []alert.Finding) alert.Finding {
	t.Helper()
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one", findings)
	}
	return findings[0]
}

// smtpProbeAbuse reports one source crossing the threshold at its last
// connection.
func smtpProbeAbuse(t *testing.T, ip string, connections int) alert.Finding {
	t.Helper()
	now := time.Now()
	tr := newSMTPProbeTracker(connections, time.Minute, time.Hour, 100, func() time.Time { return now }, nil)
	var out []alert.Finding
	for range connections {
		out = append(out, tr.Record(ip)...)
	}
	return onlyFinding(t, out)
}

func identityCandidate(path string, size int64, age time.Duration, writer string) dropperCandidate {
	observed := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
	return dropperCandidate{
		Path: path, Docroot: "/home/alice/public_html", Observed: observed,
		Birth: observed.Add(-age), BirthKnown: true, UID: 1001, Mode: 0o100644, Size: size,
		ProcInfo: writer, Head: []byte("<?php system($_POST['c']);"),
	}
}

func soloDropper(c dropperCandidate, v dropperVerdict) dropperFinding {
	return dropperFinding{Docroot: c.Docroot, Items: []dropperGone{{Cand: c, Verdict: v}}}
}

// dropperAlertFinding is the finding the engine hands its emitter.
func dropperAlertFinding(f dropperFinding) alert.Finding {
	e := newDropperEngine(dropperEngineConfig{ttl: time.Minute})
	var out alert.Finding
	e.emit = func(sev alert.Severity, check, msg, details, path, dedupKey string) {
		out = alert.Finding{Severity: sev, Check: check, Message: msg, Details: details, FilePath: path, DedupKey: dedupKey}
	}
	e.emitFinding(f)
	return out
}

// queueHealthReReports drives the ingest queue through two degradations with
// different drop totals and returns the two notices of check.
func queueHealthReReports(t *testing.T, check string) (alert.Finding, alert.Finding) {
	t.Helper()
	d := queueLifecycleDaemon(t, 1)
	previousHook := alert.CentralHook
	var events []alert.Finding
	alert.SetCentralHook(func(f alert.Finding) {
		if f.Check == check && strings.HasPrefix(f.Details, "queue=findings.ingest ") {
			events = append(events, f)
		}
	})
	t.Cleanup(func() { alert.SetCentralHook(previousHook) })
	var reporter queuehealth.Reporter
	now := time.Now()
	for i, lost := range []uint64{3, 4} {
		at := now.Add(time.Duration(i) * 10 * time.Minute)
		d.alertQueue.Lose(at, lost)
		for _, step := range []time.Duration{0, time.Minute, 2 * time.Minute} {
			d.reportQueueHealth(at.Add(step), &reporter)
		}
	}
	if len(events) != 2 {
		t.Fatalf("%s notices = %+v, want two", check, events)
	}
	return events[0], events[1]
}

func phpShieldReReport(event string) func(t *testing.T) (alert.Finding, alert.Finding) {
	return func(t *testing.T) (alert.Finding, alert.Finding) {
		line := func(account string) alert.Finding {
			f := parsePHPShieldLine("[2026-01-02 03:04:05] " + event + " ip=203.0.113.7 script=/home/" + account +
				"/public_html/wp-content/uploads/x.php uri=/wp-content/uploads/x.php ua=scanner details=cmd")
			if f == nil {
				t.Fatalf("no finding for %s", event)
			}
			return *f
		}
		return line("alice"), line("bob")
	}
}
