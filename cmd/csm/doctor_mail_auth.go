package main

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/platform"
)

// Postfix warnings and Dovecot passdb verdicts cannot establish the final
// credential result. Logging configuration must not imply SMTP coverage.
func smtpAuthLoggingDoctorChecks() []DoctorCheck {
	return smtpAuthLoggingDoctorCheck(platform.DetectMTA(), doveconfValue)
}

func smtpAuthLoggingDoctorCheck(mta platform.MTAKind, doveconf func(string) (string, error)) []DoctorCheck {
	if mta != platform.MTAPostfix {
		return nil
	}
	passwords, err := doveconf("auth_verbose_passwords")
	if errors.Is(err, exec.ErrNotFound) {
		return nil
	}
	if err != nil {
		return []DoctorCheck{{
			Name: "smtp auth logging", Status: "warn",
			Message: "Could not read Dovecot auth_verbose_passwords; SMTP password guessing is not detected",
			Fix:     "run doveconf -h auth_verbose_passwords as root, resolve the error, then rerun csm doctor",
		}}
	}
	check := DoctorCheck{
		Name: "smtp auth logging", Status: "warn",
		Message: "SMTP password guessing is not detected: available logs do not establish final credential rejections",
		Fix:     "see the SMTP detection limitations in detection-realtime.md; enabling auth_verbose does not provide safe detection",
	}
	if !strings.EqualFold(strings.TrimSpace(passwords), "no") {
		check.Message += "; Dovecot also logs passwords"
		check.Fix = "set auth_verbose_passwords = no in Dovecot logging settings, then run doveadm reload; SMTP detection remains unavailable"
	}
	return []DoctorCheck{check}
}

func doveconfValue(key string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// #nosec G204 -- the caller passes only the literal setting name above.
	out, err := exec.CommandContext(ctx, "doveconf", "-h", key).Output()
	return string(out), err
}
