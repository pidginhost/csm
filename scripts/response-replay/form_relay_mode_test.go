package main

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestReplayFormRelayMode(t *testing.T) {
	for _, mode := range []string{"", "observe", "enforce"} {
		for _, challenge := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/challenge=%v", mode, challenge), func(t *testing.T) {
				dir := t.TempDir()
				findings := writeStream(t, dir, "findings.jsonl.gz",
					event(fixtureT0, "email_php_form_relay", alert.High, "client: 203.0.113.10", ""),
					event(fixtureT0, "email_php_form_relay_observed", alert.High, "client: 203.0.113.11", ""))
				out := filepath.Join(dir, "report.json")
				args := fixtureArgs(findings, out, fmt.Sprintf("--challenge-enabled=%v", challenge))
				if mode != "" {
					args = append(args, "--php-relay-ip-recipient-mode", mode)
				}
				if err := testRun().execute(args, &bytes.Buffer{}); err != nil {
					t.Fatal(err)
				}
				report, _ := readReport(t, out)
				assertReportVocabulary(t, report)
				wantMode := mode
				if wantMode == "" {
					wantMode = "observe"
				}
				if got := sub(report, "policy")["php_relay_ip_recipient_mode"]; got != wantMode {
					t.Fatalf("report mode = %v, want %s", got, wantMode)
				}
				wantBlock, wantChallenge := 0.0, 0.0
				if mode == "enforce" {
					if challenge {
						wantChallenge = 1
					} else {
						wantBlock = 1
					}
				}
				result := sub(report, "hypothetical")
				if result["scan_blocked"] != wantBlock || result["challenge_skipped"] != wantChallenge {
					t.Fatalf("unexpected replay response: %v", result)
				}
			})
		}
	}
}

func TestReplayRejectsInvalidFormRelayMode(t *testing.T) {
	for _, mode := range []string{"", "block", "Enforce"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			args := fixtureArgs(filepath.Join(dir, "findings.jsonl.gz"), filepath.Join(dir, "report.json"), "--php-relay-ip-recipient-mode", mode)
			var stdout bytes.Buffer
			if err := testRun().execute(args, &stdout); !errors.Is(err, errPolicy) || stdout.Len() != 0 {
				t.Fatalf("invalid mode: error %v, output %q", err, stdout.String())
			}
		})
	}
}
