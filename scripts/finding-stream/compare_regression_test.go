package main

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestCompareReassignsOverlappingDecisions(t *testing.T) {
	fid := "fid-" + strings.Repeat("a", 32)
	findings := []alert.AuditEvent{{V: 1, Timestamp: compareTS, FindingID: fid, Check: "pam_bruteforce"}}
	for _, alternative := range []string{"step", "coalesced", "refused"} {
		t.Run(alternative, func(t *testing.T) {
			entry := "scan"
			other := admissionStep(fid, 0)
			other.ActionID = "aid-" + strings.Repeat("b", 32)
			if alternative == "coalesced" {
				other = summary(time.Hour, "pam_bruteforce", "coalesced", "", 1)
			}
			if alternative == "refused" {
				entry = "incident"
				other = summary(time.Hour, "unknown", "refused", "policy", 1)
				other.Entry = entry
			}
			actions := []anonAction{
				legacyBlock(fid, time.Hour, entry), legacyBlock(fid, 2*time.Hour, entry),
				admissionStep(fid, 2*time.Hour), other,
				summary(time.Hour, "pam_bruteforce", "queued", "", 1),
				summary(4*time.Hour, "pam_bruteforce", "queued", "", 1),
			}
			for range 2 {
				var out bytes.Buffer
				if err := run(compareInputs(t, findings, actions), &out); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(out.String(), "unexplained: 0: pass") {
					t.Fatalf("compatible decisions were consumed in the wrong order:\n%s", out.String())
				}
				// File order cannot change whether all legacy actions have a match.
				actions[2], actions[3] = actions[3], actions[2]
			}
		})
	}
}

func TestCompareRejectsUnlistedRefusals(t *testing.T) {
	fid := "fid-" + strings.Repeat("a", 32)
	for _, tc := range []struct{ check, entry, reason string }{
		{"cpanel_multi_ip_login", "scan", "policy"},
		{"wp_login_bruteforce", "asn_crawl", "attribution"},
	} {
		t.Run(tc.check, func(t *testing.T) {
			legacy := legacyBlock(fid, time.Minute, tc.entry)
			r := summary(time.Hour, tc.check, "refused", tc.reason, 1)
			r.Entry, r.Action = tc.entry, legacyKind(legacy)
			findings := []alert.AuditEvent{{V: 1, Timestamp: compareTS, FindingID: fid, Check: tc.check}}
			var out bytes.Buffer
			if err := run(compareInputs(t, findings, []anonAction{legacy, r}), &out); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "unexplained: 1: FAIL") {
				t.Fatalf("unlisted refusal hid a legacy action:\n%s", out.String())
			}
		})
	}
}

func TestCompareRefusesCountOverflow(t *testing.T) {
	for _, decision := range []string{"coalesced", "invalid", "queue_overflow"} {
		for _, otherEntry := range []string{"scan", "incident"} {
			t.Run(decision+"/"+otherEntry, func(t *testing.T) {
				result, refusal := decision, ""
				if decision != "coalesced" {
					result, refusal = "refused", decision
				}
				first := summary(time.Hour, "pam_bruteforce", result, refusal, math.MaxUint64)
				second := first
				second.Entry, second.Count = otherEntry, 1
				var out bytes.Buffer
				err := run(compareInputs(t, nil, []anonAction{first, second}), &out)
				if decision == "coalesced" && otherEntry != "scan" {
					if err != nil {
						t.Fatal(err)
					}
					return
				}
				if err == nil || out.Len() != 0 {
					t.Fatalf("overflow was accepted: %v\n%s", err, out.String())
				}
			})
		}
	}
}

func TestCompareConsumesEachAggregateCountOnce(t *testing.T) {
	fid := "fid-" + strings.Repeat("a", 32)
	findings := []alert.AuditEvent{{V: 1, Timestamp: compareTS, FindingID: fid, Check: "pam_bruteforce"}}
	for _, decision := range []string{"coalesced", "policy"} {
		t.Run(decision, func(t *testing.T) {
			entry := "scan"
			r := summary(time.Hour, "pam_bruteforce", "coalesced", "", 2)
			want := "matched by a coalesced admission: 2"
			if decision == "policy" {
				entry = "incident"
				r.Check, r.Entry, r.Result, r.Refusal, r.HasError = "unknown", entry, "refused", "policy", true
				want = "explained by a designed refusal: 2 (policy 2)"
			}
			actions := []anonAction{legacyBlock(fid, time.Minute, entry), legacyBlock(fid, 2*time.Minute, entry), legacyBlock(fid, 3*time.Minute, entry), r}
			var out bytes.Buffer
			if err := run(compareInputs(t, findings, actions), &out); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), want) || !strings.Contains(out.String(), "unexplained: 1: FAIL") {
				t.Fatalf("aggregate capacity was lost or spent twice:\n%s", out.String())
			}
		})
	}
}

func TestCompareAcceptsUnstampedFindingRows(t *testing.T) {
	fid := "fid-" + strings.Repeat("a", 32)
	findings := []alert.AuditEvent{{V: 1, FindingID: fid, Check: "pam_bruteforce"}}
	actions := []anonAction{legacyBlock(fid, time.Minute, "scan"), admissionStep(fid, time.Minute), summary(time.Hour, "pam_bruteforce", "queued", "", 1)}
	var out bytes.Buffer
	if err := run(compareInputs(t, findings, actions), &out); err != nil {
		t.Fatalf("anonymized recordings retain older unstamped findings: %v", err)
	}
	if !strings.Contains(out.String(), "matched by an admission step: 1") || !strings.Contains(out.String(), "unexplained: 0: pass") {
		t.Fatalf("unstamped finding lost its join:\n%s", out.String())
	}
}

type privateErrorWriter struct{}

func (privateErrorWriter) Write([]byte) (int, error) {
	return 0, errors.New("write /home/example-account/report: customer.example")
}

func TestCompareOutputErrorsNeverRepeatPrivateInput(t *testing.T) {
	err := run(compareInputs(t, nil, nil), privateErrorWriter{})
	if err == nil || strings.Contains(err.Error(), "example-account") || strings.Contains(err.Error(), "customer.example") {
		t.Fatalf("unsafe output error: %v", err)
	}
}
