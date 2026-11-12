package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/stalwartlog"
)

const (
	// stalwartDoctorTailLines is how many recent lines the format check reads.
	stalwartDoctorTailLines = 200
	// stalwartDoctorTailBytes bounds the read for those lines.
	stalwartDoctorTailBytes = 256 * 1024
)

func stalwartLogDoctorChecks(cfg *config.Config) []DoctorCheck {
	return stalwartLogDoctorCheck(platform.DetectMTA(), cfg.Stalwart, time.Now())
}

// stalwartLogDoctorCheck reports, on a Stalwart host, whether CSM finds a
// current log, whether its recent lines are in the layout CSM reads, and
// whether Stalwart logs rejected logins at all.
func stalwartLogDoctorCheck(mta platform.MTAKind, sc config.StalwartConfig, now time.Time) []DoctorCheck {
	if mta != platform.MTAStalwart {
		return nil
	}
	path, err := stalwartlog.NewestFile(sc.LogDir, sc.LogPrefix)
	if err != nil {
		return []DoctorCheck{{
			Name:    "stalwart log",
			Status:  "fail",
			Message: fmt.Sprintf("No Stalwart log found (%v), so CSM sees no mail logins or sends", err),
			Fix:     "check stalwart.log_dir and log_prefix, and that Stalwart's file log is enabled",
		}}
	}
	checks := []DoctorCheck{stalwartLogAgeCheck(path, sc.LogPrefix, now)}
	lines, err := tailLines(path, stalwartDoctorTailLines, stalwartDoctorTailBytes)
	if err != nil {
		return append(checks, DoctorCheck{Name: "stalwart log format", Status: "fail", Message: "Could not read " + path + ": " + err.Error()})
	}
	checks = append(checks, stalwartFormatCheck(lines))
	return append(checks, stalwartFailedLoginCheck(path))
}

func stalwartLogAgeCheck(path, prefix string, now time.Time) DoctorCheck {
	check := DoctorCheck{Name: "stalwart log", Status: "ok", Message: "Reading " + path}
	day, err := time.Parse("2006-01-02", strings.TrimPrefix(filepath.Base(path), prefix+"."))
	if err == nil && now.UTC().Sub(day) > 48*time.Hour {
		check.Status = "warn"
		check.Message = "The newest Stalwart log is " + path + ", more than a day old, so CSM sees no recent mail logins or sends"
		check.Fix = "check that Stalwart is running and still writes its file log to stalwart.log_dir"
	}
	return check
}

func stalwartFormatCheck(lines []string) DoctorCheck {
	total, parsed := 0, 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		total++
		if _, ok := stalwartlog.Parse(line); ok {
			parsed++
		}
	}
	check := DoctorCheck{Name: "stalwart log format", Status: "ok", Message: fmt.Sprintf("%d of the last %d lines are in the layout CSM reads", parsed, total)}
	switch {
	case total == 0:
		check.Message = "The newest Stalwart log is empty so far"
	case parsed == 0:
		check.Status = "fail"
		check.Message = fmt.Sprintf("None of the last %d lines are in the layout CSM reads, so CSM sees no mail logins or sends", total)
		check.Fix = "check that Stalwart's file log is in text format without ANSI colors; a Stalwart upgrade may have changed its layout"
	case parsed < total:
		check.Status = "warn"
	}
	return check
}

// stalwartFailedLoginCheck reports whether the newest log holds a rejected
// login. Stalwart logs them at debug level unless the event is raised.
func stalwartFailedLoginCheck(path string) DoctorCheck {
	check := DoctorCheck{Name: "stalwart failed logins", Status: "ok", Message: "Stalwart logs rejected logins"}
	found, err := logHasEvent(path, "auth.failed")
	if err != nil {
		check.Status = "warn"
		check.Message = "Could not read " + path + ": " + err.Error()
		return check
	}
	if !found {
		check.Status = "warn"
		check.Message = "Stalwart logs no rejected logins, so password guessing over SMTP, IMAP and POP3 is not detected"
		check.Fix = "raise the auth.failed event to the info level in Stalwart's logging settings"
	}
	return check
}

func logHasEvent(path, name string) (bool, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-configured Stalwart log path
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	marker := "(" + name + ")"
	r := bufio.NewReaderSize(f, 64*1024)
	discard := false
	for {
		line, prefix, err := r.ReadLine()
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		// Oversized records must not hide later logins or let their tail
		// masquerade as a separate event.
		if discard || prefix {
			discard = prefix
			continue
		}
		if !bytes.Contains(line, []byte(marker)) {
			continue
		}
		if ev, ok := stalwartlog.Parse(string(line)); ok && ev.Name == name {
			return true, nil
		}
	}
}

// tailLines returns up to n complete lines from the last maxBytes of path.
func tailLines(path string, n int, maxBytes int64) ([]string, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-configured Stalwart log path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	offset := max(st.Size()-maxBytes, 0)
	buf := make([]byte, st.Size()-offset)
	if _, err := f.ReadAt(buf, offset); err != nil && err != io.EOF {
		return nil, err
	}
	if offset > 0 {
		// The first line may start before the window.
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		}
	}
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}
