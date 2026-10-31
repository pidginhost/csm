package main

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/platform"
)

// smtpAuthLoggingDoctorChecks reports whether Dovecot logs the rejections the
// daemon pairs with Postfix failures to detect SMTP password guessing.
func smtpAuthLoggingDoctorChecks() []DoctorCheck {
	return smtpAuthLoggingDoctorCheck(platform.DetectMTA(), doveconfValue)
}

// smtpAuthLoggingDoctorCheck applies the rule to an MTA and a doveconf
// lookup. Exim logs its own SMTP AUTH failures, and a Postfix host without
// doveconf uses another SASL provider, so both return nothing.
func smtpAuthLoggingDoctorCheck(mta platform.MTAKind, doveconf func(string) (string, error)) []DoctorCheck {
	if mta != platform.MTAPostfix {
		return nil
	}
	values := map[string]string{}
	for _, key := range []string{"auth_verbose", "auth_verbose_passwords"} {
		value, err := doveconf(key)
		if errors.Is(err, exec.ErrNotFound) {
			return nil
		}
		if err != nil {
			return []DoctorCheck{{
				Name:    "smtp auth logging",
				Status:  "warn",
				Message: "Could not read Dovecot " + key + "; SMTP password guessing may not be detected",
				Fix:     "run doveconf -h " + key + " as root, resolve the error, then rerun csm doctor",
			}}
		}
		values[key] = strings.TrimSpace(value)
	}
	check := DoctorCheck{Name: "smtp auth logging", Status: "ok", Message: "Dovecot logs rejected SMTP logins"}
	switch {
	case !strings.EqualFold(values["auth_verbose"], "yes"):
		check.Status = "warn"
		check.Message = "Dovecot does not log rejected logins, so SMTP password guessing is not detected"
		check.Fix = "set auth_verbose = yes in /etc/dovecot/conf.d/10-logging.conf, then run doveadm reload"
	case !strings.EqualFold(values["auth_verbose_passwords"], "no"):
		check.Status = "warn"
		check.Message = "Dovecot logs the passwords of failed logins; those lines are not used for SMTP detection"
		check.Fix = "set auth_verbose_passwords = no in /etc/dovecot/conf.d/10-logging.conf, then run doveadm reload"
	}
	return []DoctorCheck{check}
}

// doveconfValue returns one Dovecot setting as doveconf resolves it.
func doveconfValue(key string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// #nosec G204 -- callers pass only the literal setting names above.
	out, err := exec.CommandContext(ctx, "doveconf", "-h", key).Output()
	return string(out), err
}
