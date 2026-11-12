package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/stalwartapi"
	"github.com/pidginhost/csm/internal/stalwartlog"
	"github.com/pidginhost/csm/internal/stalwartsetup"
)

const (
	// stalwartDoctorTailLines is how many recent lines the format check reads.
	stalwartDoctorTailLines = 200
	// stalwartDoctorTailBytes bounds the read for those lines.
	stalwartDoctorTailBytes = 256 * 1024
)

// stalwartDoctorChecks runs the Stalwart checks: the log checks, what the
// log shows about client addresses and bans, and Stalwart's settings when an
// admin login is in the environment.
func stalwartDoctorChecks(cfg *config.Config, automation health.AutomationStatus) []DoctorCheck {
	mta := platform.DetectMTA()
	if mta != platform.MTAStalwart {
		return nil
	}
	now := time.Now()
	out := stalwartLogDoctorCheck(mta, cfg.Stalwart, now)
	if path, err := stalwartlog.NewestFile(cfg.Stalwart.LogDir, cfg.Stalwart.LogPrefix, now); err == nil {
		if lines, err := tailLines(path, stalwartDoctorTailLines, stalwartDoctorTailBytes); err == nil {
			// Config load validated the mappings.
			ports, _ := stalwartlog.ParsePorts(cfg.Stalwart.Ports)
			out = append(out,
				stalwartForwardedCheck(lines, ports, automation.FirewallLocalPortLocks),
				stalwartCDNBanCheck(lines, func(ip string) bool { return checks.KnownProxyPeer(ip, cfg) }))
		}
	}
	in := stalwartInputs(cfg, platform.Detect().WebServerUsers(), &automation)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	newAPI := func(url, user, password string) stalwartsetup.API { return stalwartapi.New(url, user, password) }
	return append(out, stalwartSettingsDoctorChecks(ctx, os.Getenv, newAPI, cfg.Stalwart, in)...)
}

// stalwartLogDoctorCheck reports, on a Stalwart host, whether CSM finds a
// current log, whether its recent lines are in the layout CSM reads, and
// whether Stalwart logs rejected logins at all.
func stalwartLogDoctorCheck(mta platform.MTAKind, sc config.StalwartConfig, now time.Time) []DoctorCheck {
	if mta != platform.MTAStalwart {
		return nil
	}
	path, err := stalwartlog.NewestFile(sc.LogDir, sc.LogPrefix, now)
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
		check.Fix = "run csm stalwart setup"
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

// stalwartSettingsDoctorChecks reports each setup step read-only. It needs
// an admin login, which only the environment supplies.
func stalwartSettingsDoctorChecks(ctx context.Context, getenv func(string) string, newAPI func(url, user, password string) stalwartsetup.API, sc config.StalwartConfig, in stalwartsetup.Inputs) (result []DoctorCheck) {
	user, password := getenv("STALWART_USER"), getenv("STALWART_PASSWORD")
	if user == "" || password == "" {
		return []DoctorCheck{{Name: "stalwart settings", Status: "ok",
			Message: "Not checked; set STALWART_USER and STALWART_PASSWORD to a Stalwart admin login to check Stalwart's settings"}}
	}
	defer func() {
		for i := range result {
			result[i].Name = stalwartapi.Redact(result[i].Name, user, password)
			result[i].Message = stalwartapi.Redact(result[i].Message, user, password)
			result[i].Fix = stalwartapi.Redact(result[i].Fix, user, password)
		}
	}()
	if !stalwartapi.LocalURL(sc.APIURL) {
		in.LockManaged = false
		in.LockedPorts = nil
	}
	plan, err := stalwartsetup.Inspect(ctx, newAPI(sc.APIURL, user, password), in)
	if err != nil {
		return []DoctorCheck{{Name: "stalwart settings", Status: "warn",
			Message: "Cannot read Stalwart's settings at " + sc.APIURL + ": " + strings.ReplaceAll(err.Error(), password, "[redacted]"),
			Fix:     "check stalwart.api_url and the admin login"}}
	}
	return stalwartStepChecks(plan)
}

func stalwartStepChecks(plan stalwartsetup.Plan) []DoctorCheck {
	checks := make([]DoctorCheck, 0, len(plan.Steps))
	for _, s := range plan.Steps {
		c := DoctorCheck{Name: "stalwart " + s.Name, Status: "ok", Message: s.Detail}
		switch s.State {
		case stalwartsetup.Change:
			c.Status, c.Fix = "warn", "run csm stalwart setup"
		case stalwartsetup.Unsafe:
			c.Status = "fail"
		case stalwartsetup.Warn:
			c.Status = "warn"
		}
		checks = append(checks, c)
	}
	return checks
}

// stalwartForwardedCheck looks for logins on an HTTP listener that name a
// client other than this host. Behind a web server that means Stalwart takes
// the address from a forwarded header, which anyone who can connect can
// forge unless CSM locks the port. A listener clients reach directly logs
// the same way, and the log cannot tell the two apart, so this warns.
func stalwartForwardedCheck(lines []string, ports stalwartlog.Ports, lockedPorts []int) DoctorCheck {
	check := DoctorCheck{Name: "stalwart webmail addresses", Status: "ok", Message: "No webmail login from another host on an unlocked port in the recent log"}
	for _, line := range lines {
		ev, ok := stalwartlog.Parse(line)
		if !ok || (ev.Name != "auth.failed" && ev.Name != "auth.success") {
			continue
		}
		s, ok := ev.Session()
		if !ok || ports.Of(s.LocalPort) != stalwartlog.ProtoHTTP || s.RemoteIP.Unmap().IsLoopback() || slices.Contains(lockedPorts, int(s.LocalPort)) {
			continue
		}
		check.Status = "warn"
		check.Message = fmt.Sprintf("Stalwart's HTTP listener on port %d logged a login from %s, and CSM does not lock that port. If Stalwart takes the address from a forwarded header, any local user can make it name, and ban, any address", s.LocalPort, s.RemoteIP)
		check.Fix = "run csm stalwart setup --dry-run to see what is missing"
		return check
	}
	return check
}

// stalwartCDNBanCheck looks for Stalwart bans of a CDN or proxy edge
// address, which lock out every client behind that edge.
func stalwartCDNBanCheck(lines []string, isCDN func(string) bool) DoctorCheck {
	check := DoctorCheck{Name: "stalwart proxy bans", Status: "ok", Message: "No ban of a CDN or proxy address in the recent log"}
	for _, line := range lines {
		ev, ok := stalwartlog.Parse(line)
		if !ok || !strings.HasPrefix(ev.Name, "security.") || !strings.HasSuffix(ev.Name, "-ban") {
			continue
		}
		s, ok := ev.Session()
		if !ok || !isCDN(s.RemoteIP.String()) {
			continue
		}
		check.Status = "warn"
		check.Message = fmt.Sprintf("Stalwart banned %s, a CDN or proxy address, which locks out every client behind it", s.RemoteIP)
		check.Fix = "make Stalwart see the client address behind the proxy, or reach Stalwart without the proxy"
		return check
	}
	return check
}
