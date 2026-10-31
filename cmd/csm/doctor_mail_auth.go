package main

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/platform"
)

// smtpAuthLoggingDoctorChecks reports whether Dovecot logs the verdicts the
// daemon reads to detect SMTP password guessing on a Postfix host.
func smtpAuthLoggingDoctorChecks() []DoctorCheck {
	return smtpAuthLoggingDoctorCheck(platform.DetectMTA(), doveconfValue)
}

// smtpAuthLoggingDoctorCheck applies the rule to an MTA and a doveconf
// lookup. Exim logs its own SMTP AUTH failures. A missing doveconf can mean
// Postfix uses another SASL provider; other lookup errors need attention.
func smtpAuthLoggingDoctorCheck(mta platform.MTAKind, doveconf func(string) (string, error)) []DoctorCheck {
	if mta != platform.MTAPostfix {
		return nil
	}
	verbose, err := doveconf("auth_verbose")
	if errors.Is(err, exec.ErrNotFound) {
		return nil
	}
	if err != nil {
		return smtpAuthLoggingLookupWarning("auth_verbose")
	}
	passwords, err := doveconf("auth_verbose_passwords")
	if err != nil {
		return smtpAuthLoggingLookupWarning("auth_verbose_passwords")
	}
	check := DoctorCheck{Name: "smtp auth logging", Status: "ok", Message: "Dovecot logs rejected SMTP logins"}
	switch {
	case !strings.EqualFold(strings.TrimSpace(verbose), "yes"):
		check.Status = "warn"
		check.Message = "Dovecot does not log rejected logins, so SMTP password guessing is not detected"
		check.Fix = "set auth_verbose = yes in /etc/dovecot/conf.d/10-logging.conf, then run doveadm reload"
	case !strings.EqualFold(strings.TrimSpace(passwords), "no"):
		check.Status = "warn"
		check.Message = "Dovecot logs the passwords of failed logins; those lines are not used for SMTP detection"
		check.Fix = "set auth_verbose_passwords = no in /etc/dovecot/conf.d/10-logging.conf, then run doveadm reload"
	}
	return []DoctorCheck{check}
}

func smtpAuthLoggingLookupWarning(key string) []DoctorCheck {
	return []DoctorCheck{{
		Name: "smtp auth logging", Status: "warn",
		Message: "Could not read Dovecot " + key + "; SMTP auth logging is unverified",
		Fix:     "run doveconf -h " + key + " as root, resolve the error, then rerun csm doctor",
	}}
}

// doveconfValue returns one Dovecot setting as doveconf resolves it.
func doveconfValue(key string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// #nosec G204 -- callers pass only the literal setting names above.
	out, err := exec.CommandContext(ctx, "doveconf", "-h", key).Output()
	return string(out), err
}
