package main

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

// Verbose database results cannot prove whether an SMTP login failed.
// No logging setting can make this unsupported evidence source safe.
func TestSMTPAuthLoggingDoctorReportsDetectionGap(t *testing.T) {
	for _, verbose := range []string{"yes", "no"} {
		for _, passwords := range []string{"no", "No", " no\n"} {
			checks := smtpAuthLoggingDoctorCheck(platform.MTAPostfix, func(key string) (string, error) {
				if key == "auth_verbose" {
					return verbose, nil
				}
				if key == "auth_verbose_passwords" {
					return passwords, nil
				}
				t.Fatalf("unexpected setting %q", key)
				return "", nil
			})
			if len(checks) != 1 || checks[0].Status != "warn" || !strings.Contains(checks[0].Message, "not detected") || strings.Contains(checks[0].Fix, "auth_verbose = yes") {
				t.Fatalf("checks = %+v, want an explicit detection-gap warning", checks)
			}
			if strings.Contains(checks[0].Message, "logs passwords") || strings.Contains(checks[0].Fix, "auth_verbose_passwords = no") {
				t.Fatalf("auth_verbose_passwords=%q: disabled password logging was reported as enabled: %+v", passwords, checks)
			}
		}
	}
}

func TestSMTPAuthLoggingDoctorWarnsWhenPasswordsAreLogged(t *testing.T) {
	for _, value := range []string{"plain", "sha1", "plain:8", "yes"} {
		checks := smtpAuthLoggingDoctorCheck(platform.MTAPostfix, func(string) (string, error) { return value, nil })
		if len(checks) != 1 || checks[0].Status != "warn" || !strings.Contains(checks[0].Fix, "auth_verbose_passwords = no") || !strings.Contains(checks[0].Message, "not detected") {
			t.Fatalf("auth_verbose_passwords=%s: checks = %+v, want password logging and detection-gap warning", value, checks)
		}
	}
}

func TestSMTPAuthLoggingDoctorSkipped(t *testing.T) {
	for _, mta := range []platform.MTAKind{platform.MTAExim, platform.MTAUnknown} {
		checks := smtpAuthLoggingDoctorCheck(mta, func(string) (string, error) {
			t.Fatal("queried Dovecot on a host without Postfix")
			return "", nil
		})
		if len(checks) != 0 {
			t.Fatalf("MTA %v: checks = %+v, want none", mta, checks)
		}
	}
	noDovecot := func(string) (string, error) { return "", &exec.Error{Name: "doveconf", Err: exec.ErrNotFound} }
	if checks := smtpAuthLoggingDoctorCheck(platform.MTAPostfix, noDovecot); len(checks) != 0 {
		t.Fatalf("no Dovecot: checks = %+v, want none", checks)
	}
}

func TestSMTPAuthLoggingDoctorReportsLookupFailures(t *testing.T) {
	for _, err := range []error{context.DeadlineExceeded, errors.New("configuration unreadable")} {
		checks := smtpAuthLoggingDoctorCheck(platform.MTAPostfix, func(string) (string, error) { return "", err })
		if len(checks) != 1 || checks[0].Status != "warn" || !strings.Contains(checks[0].Message, "auth_verbose_passwords") || !strings.Contains(checks[0].Message, "not detected") || checks[0].Fix == "" {
			t.Fatalf("lookup failure: checks = %+v, want one actionable warning", checks)
		}
	}
}
