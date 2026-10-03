package attackdb

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestClassify_SMTPChecksAsBruteForce(t *testing.T) {
	for _, check := range []string{"smtp_bruteforce", "smtp_subnet_spray"} {
		got := checkToAttack[check]
		if got != AttackBruteForce {
			t.Errorf("%q classified as %q, want %q", check, got, AttackBruteForce)
		}
	}
}

func TestClassify_MailChecksAsBruteForce(t *testing.T) {
	for _, check := range []string{"mail_bruteforce", "mail_subnet_spray", "mail_account_compromised"} {
		got := checkToAttack[check]
		if got != AttackBruteForce {
			t.Errorf("%q classified as %q, want %q", check, got, AttackBruteForce)
		}
	}
}

func TestClassify_AdminPanelBruteForceAsBruteForce(t *testing.T) {
	got := checkToAttack["admin_panel_bruteforce"]
	if got != AttackBruteForce {
		t.Errorf("admin_panel_bruteforce classified as %q, want %q", got, AttackBruteForce)
	}
}

func TestClassify_CredentialStuffingAsBruteForce(t *testing.T) {
	got := checkToAttack["credential_stuffing"]
	if got != AttackBruteForce {
		t.Errorf("credential_stuffing classified as %q, want %q", got, AttackBruteForce)
	}
}

func TestClassify_EmailAuthFailureRealtimeIsNotScored(t *testing.T) {
	// Per-event dovecot/exim auth failures are visibility. The SMTP and mail
	// trackers turn them into blockable findings with success, established
	// source and auth backend outage guards; scoring the raw events here let
	// local_threat_score block around those guards.
	if got, ok := checkToAttack["email_auth_failure_realtime"]; ok {
		t.Errorf("email_auth_failure_realtime classified as %q, want unscored", got)
	}
}

func TestRecordFinding_EmailAuthFailureBuildsNoRecord(t *testing.T) {
	db := newTestDB(t)
	ts := time.Date(2026, 6, 7, 5, 35, 0, 0, time.UTC)
	for i := 0; i < 20; i++ {
		db.RecordFinding(alert.Finding{
			Check:     "email_auth_failure_realtime",
			Message:   "Email authentication failure",
			Severity:  alert.High,
			SourceIP:  "203.0.113.7",
			Mailbox:   "owner",
			Domain:    "example.test",
			Timestamp: ts.Add(time.Duration(i) * time.Minute),
		})
	}
	if rec := db.LookupIP("203.0.113.7"); rec != nil {
		t.Fatalf("mail auth failures created an attack-DB record with score %d", rec.ThreatScore)
	}
}

func TestRecordFinding_SlowEmailAuthFailuresStayBelowBlockScore(t *testing.T) {
	db := newTestDB(t)
	ts := time.Date(2026, 6, 1, 5, 35, 0, 0, time.UTC)
	for i := 0; i < 50; i++ {
		db.RecordFinding(alert.Finding{
			Check:     "email_auth_failure_realtime",
			Message:   "Email authentication failure for owner from 203.0.113.9",
			SourceIP:  "203.0.113.9",
			Severity:  alert.High,
			Timestamp: ts.Add(time.Duration(i) * 5 * time.Minute),
		})
	}
	if rec := db.LookupIP("203.0.113.9"); rec != nil && rec.ThreatScore >= 70 {
		t.Errorf("slow auth-failure score = %d, want < 70", rec.ThreatScore)
	}
}

func TestRecordFinding_FastEmailAuthFailuresStayBelowBlockScore(t *testing.T) {
	db := newTestDB(t)
	ts := time.Date(2026, 6, 1, 5, 35, 0, 0, time.UTC)
	for i := 0; i < 50; i++ {
		db.RecordFinding(alert.Finding{
			Check:     "email_auth_failure_realtime",
			Message:   "Email authentication failure for owner from 203.0.113.12",
			SourceIP:  "203.0.113.12",
			Severity:  alert.High,
			Timestamp: ts.Add(time.Duration(i) * 20 * time.Second),
		})
	}
	// A fast attacker is blocked by the SMTP tracker's own smtp_bruteforce.
	if rec := db.LookupIP("203.0.113.12"); rec != nil && rec.ThreatScore >= 70 {
		t.Errorf("fast auth-failure score = %d, want < 70", rec.ThreatScore)
	}
}

func TestRecordFinding_NonMailBruteDoesNotSetSustainedScoreTier(t *testing.T) {
	db := newTestDB(t)
	ts := time.Date(2026, 6, 1, 5, 35, 0, 0, time.UTC)
	for i := 0; i < 50; i++ {
		db.RecordFinding(alert.Finding{
			Check:     "wp_login_bruteforce",
			Message:   "WordPress brute force from 203.0.113.13",
			SourceIP:  "203.0.113.13",
			Severity:  alert.Critical,
			Timestamp: ts.Add(time.Duration(i) * 20 * time.Second),
		})
	}
	rec := db.LookupIP("203.0.113.13")
	if rec == nil {
		t.Fatal("wp brute findings did not create an attack-DB record")
	}
	if rec.ThreatScore >= 70 {
		t.Errorf("non-mail brute score = %d, want < 70 (the producer blocks, not the score)", rec.ThreatScore)
	}
}

func TestRecordFinding_MailAuthFailuresAddNothingToLaterEvidence(t *testing.T) {
	db := newTestDB(t)
	ts := time.Date(2026, 6, 1, 5, 35, 0, 0, time.UTC)
	for i := 0; i < 50; i++ {
		db.RecordFinding(alert.Finding{
			Check:     "email_auth_failure_realtime",
			Message:   "Email authentication failure for owner from 203.0.113.14",
			SourceIP:  "203.0.113.14",
			Severity:  alert.High,
			Timestamp: ts.Add(time.Duration(i) * 20 * time.Second),
		})
	}
	db.RecordFinding(alert.Finding{
		Check:     "http_scanner_profile",
		Message:   "Scanner profile from 203.0.113.14",
		SourceIP:  "203.0.113.14",
		Severity:  alert.High,
		Timestamp: ts.Add(40 * time.Minute),
	})
	rec := db.LookupIP("203.0.113.14")
	if rec == nil {
		t.Fatal("scanner finding created no record")
	}
	if rec.EventCount != 1 || rec.AttackCounts[AttackBruteForce] != 0 || rec.ThreatScore >= 70 {
		t.Errorf("record %+v: mail auth failures added to the scanner evidence", rec)
	}
}

// A record stored by an older daemon can carry the removed sustained-brute
// marker and the score it earned. Loading it recomputes the score without it.
func TestNormalizeLoadedRecordRescoresLegacySustainedBrute(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	legacy := `{"ip":"203.0.113.10","first_seen":"` + now + `","last_seen":"` + now + `","event_count":1255,` +
		`"attack_counts":{"brute_force":1255},"accounts":{"victim@example.test":1255},"threat_score":85,` +
		`"brute_force_window_start":"` + now + `","brute_force_window_count":1255,"brute_force_sustained_at":"` + now + `"}`
	var rec IPRecord
	if err := json.Unmarshal([]byte(legacy), &rec); err != nil {
		t.Fatal(err)
	}
	if changed, _ := normalizeLoadedRecord(&rec); !changed {
		t.Error("legacy score was not marked for rewrite")
	}
	if rec.ThreatScore >= 70 {
		t.Errorf("legacy sustained-brute record rescored to %d, want < 70", rec.ThreatScore)
	}
}

func TestNormalizeLoadedRecordDoesNotBackfillSlowBruteWindow(t *testing.T) {
	now := time.Now()
	rec := &IPRecord{
		IP:           "203.0.113.11",
		FirstSeen:    now.Add(-4 * time.Hour),
		LastSeen:     now,
		EventCount:   50,
		AttackCounts: map[AttackType]int{AttackBruteForce: 50},
		Accounts:     map[string]int{"owner@example.test": 50},
	}
	normalizeLoadedRecord(rec)
	if rec.ThreatScore >= 70 {
		t.Errorf("ThreatScore = %d, want < 70", rec.ThreatScore)
	}
}

// The per-IP HTTP-abuse detectors carry a source IP and must feed the attack
// DB so a repeat HTTP scanner / flooder builds local reputation. They are
// reconnaissance/abuse signals, not credential brute force, so they classify
// as recon (volume-scored, no brute-force bonus).
func TestClassify_HTTPAbuseChecksAsRecon(t *testing.T) {
	for _, check := range []string{"http_scanner_profile", "http_request_flood", "http_claimed_bot_unverified", "http_ua_spoof"} {
		if got := checkToAttack[check]; got != AttackRecon {
			t.Errorf("%q classified as %q, want %q", check, got, AttackRecon)
		}
	}
}

func TestRecordFinding_HTTPAbuseChecksBuildReputation(t *testing.T) {
	cases := []struct {
		check   string
		message string
	}{
		{
			check:   "http_scanner_profile",
			message: "URL scanner profile from 203.0.113.45: 40 of 42 requests hit probe-error statuses",
		},
		{
			check:   "http_request_flood",
			message: "HTTP request flood from 203.0.113.45: 250 requests",
		},
		{
			check:   "http_claimed_bot_unverified",
			message: "Unverified claimed bot from 203.0.113.45: request flood",
		},
		{
			check:   "http_ua_spoof",
			message: "User-Agent spoof from 203.0.113.45: known scanner UA",
		},
	}

	for _, tc := range cases {
		t.Run(tc.check, func(t *testing.T) {
			db := NewForTest(nil)
			db.RecordFinding(alert.Finding{
				Check:     tc.check,
				SourceIP:  "203.0.113.45",
				Message:   tc.message,
				Timestamp: time.Date(2026, 6, 13, 10, 31, 0, 0, time.UTC),
			})

			rec := db.LookupIP("203.0.113.45")
			if rec == nil {
				t.Fatalf("%s finding built no attack record", tc.check)
			}
			if rec.EventCount != 1 {
				t.Errorf("EventCount = %d, want 1", rec.EventCount)
			}
			if rec.AttackCounts[AttackRecon] != 1 {
				t.Errorf("AttackCounts[recon] = %d, want 1", rec.AttackCounts[AttackRecon])
			}
			if rec.AttackCounts[AttackBruteForce] != 0 {
				t.Errorf("AttackCounts[brute_force] = %d, want 0", rec.AttackCounts[AttackBruteForce])
			}
			if rec.ThreatScore != 2 {
				t.Errorf("ThreatScore = %d, want 2 for one recon event", rec.ThreatScore)
			}
		})
	}
}

// http_distributed_flood is an aggregate per-vhost finding with no single
// source IP, so it is intentionally absent from the classifier: RecordFinding
// has no IP to attribute and records nothing.
func TestRecordFinding_HTTPDistributedFloodNotRecordedWithoutIP(t *testing.T) {
	if attackType, ok := checkToAttack["http_distributed_flood"]; ok {
		t.Fatalf("http_distributed_flood classified as %q, want absent", attackType)
	}

	db := NewForTest(nil)
	db.RecordFinding(alert.Finding{
		Check:     "http_distributed_flood",
		Domain:    "victim.example",
		Message:   "Distributed HTTP attack on victim.example: 6 distinct abusive source IPs",
		Timestamp: time.Now(),
	})
	if n := db.TotalIPs(); n != 0 {
		t.Errorf("TotalIPs = %d, want 0 (aggregate finding has no source IP)", n)
	}
}

// Every attack type has one display label, shared by the Web UI pages that
// chart or badge attack types.
func TestAttackTypeLabelsCoverEveryType(t *testing.T) {
	all := []AttackType{AttackBruteForce, AttackWAFBlock, AttackWebshell, AttackPhishing, AttackC2, AttackRecon,
		AttackSPAM, AttackCPanelLogin, AttackFileUpload, AttackAuthSuccess, AttackReputation, AttackOther}
	labels := AttackTypeLabels()
	if len(labels) != len(all) {
		t.Fatalf("%d labels for %d attack types", len(labels), len(all))
	}
	seen := map[string]AttackType{}
	for _, typ := range all {
		label := labels[string(typ)]
		if label == "" || label == string(typ) {
			t.Errorf("%s has no display label", typ)
		}
		if prev, dup := seen[label]; dup {
			t.Errorf("%s and %s share the label %q", typ, prev, label)
		}
		seen[label] = typ
	}
}
