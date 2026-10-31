package main

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

func doveconfValues(verbose, passwords string) func(string) (string, error) {
	return func(key string) (string, error) {
		switch key {
		case "auth_verbose":
			return verbose, nil
		case "auth_verbose_passwords":
			return passwords, nil
		}
		return "", errors.New("unexpected key " + key)
	}
}

// SMTP AUTH on Postfix is detected by pairing Postfix failures with Dovecot's
// rejection lines, which Dovecot writes only with auth_verbose on.
func TestSMTPAuthLoggingDoctorWarnsWhenDovecotIsQuiet(t *testing.T) {
	checks := smtpAuthLoggingDoctorCheck(platform.MTAPostfix, doveconfValues("no", "no"))
	if len(checks) != 1 || checks[0].Status != "warn" || !strings.Contains(checks[0].Message, "not detected") || !strings.Contains(checks[0].Fix, "auth_verbose = yes") {
		t.Fatalf("checks = %+v, want one warn naming auth_verbose = yes", checks)
	}
}

func TestSMTPAuthLoggingDoctorWarnsWhenPasswordsAreLogged(t *testing.T) {
	for _, value := range []string{"plain", "sha1", "plain:8", "yes"} {
		checks := smtpAuthLoggingDoctorCheck(platform.MTAPostfix, doveconfValues("yes", value))
		if len(checks) != 1 || checks[0].Status != "warn" || !strings.Contains(checks[0].Fix, "auth_verbose_passwords = no") {
			t.Fatalf("auth_verbose_passwords=%s: checks = %+v, want one warn naming auth_verbose_passwords = no", value, checks)
		}
	}
}

func TestSMTPAuthLoggingDoctorOK(t *testing.T) {
	for _, passwords := range []string{"no", "No", " no\n"} {
		checks := smtpAuthLoggingDoctorCheck(platform.MTAPostfix, doveconfValues("yes\n", passwords))
		if len(checks) != 1 || checks[0].Status != "ok" {
			t.Fatalf("auth_verbose_passwords=%q: checks = %+v, want one ok", passwords, checks)
		}
	}
}

// Exim logs its own SMTP AUTH failures; a Postfix host without Dovecot has
// no verdicts to read.
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
	for _, key := range []string{"auth_verbose", "auth_verbose_passwords"} {
		for _, err := range []error{context.DeadlineExceeded, errors.New("configuration unreadable")} {
			checks := smtpAuthLoggingDoctorCheck(platform.MTAPostfix, func(k string) (string, error) {
				if k == key {
					return "", err
				}
				return doveconfValues("yes", "no")(k)
			})
			if len(checks) != 1 || checks[0].Status != "warn" || !strings.Contains(checks[0].Message, key) || checks[0].Fix == "" {
				t.Fatalf("%s lookup failure: checks = %+v, want one actionable warning", key, checks)
			}
		}
	}
}
