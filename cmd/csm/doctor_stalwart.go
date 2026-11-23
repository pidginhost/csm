package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/ipmap"
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
// log shows about client addresses and bans, CSM's API key, and Stalwart's
// settings through that key or an admin login in the environment.
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
	in := stalwartInputs(cfg, platform.Detect().WebServerUsers(), &automation, platform.PHPRuntimeUsers)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	newAPI := func(url, user, password string) stalwartDoctorAPI {
		return stalwartapi.NewWithPeerCheck(url, user, password, stalwartapi.CheckPeer)
	}
	newKeyAPI := func(url, key string) stalwartDoctorAPI {
		return stalwartapi.NewKey(url, key, stalwartapi.CheckPeer)
	}
	return append(out, stalwartSettingsDoctorChecks(ctx, os.Getenv, newAPI, newKeyAPI, stalwartapi.CheckListener, cfg.Stalwart, in)...)
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
	checks = append(checks, stalwartFormatCheck(lines), stalwartFailedLoginCheck(path))
	if c, ok := stalwartClassifierCheck(path); ok {
		checks = append(checks, c)
	}
	return checks
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

// stalwartClassifierCheck reports the newest classifier run that ended for
// lack of samples. A training start after it may have succeeded silently,
// so then it says nothing.
func stalwartClassifierCheck(path string) (DoctorCheck, bool) {
	var last *stalwartlog.Event
	err := scanLogEvents(path, []string{"spam.model-not-ready", "spam.train-started"}, func(ev stalwartlog.Event, complete bool) bool {
		last = nil
		if complete && ev.Name == "spam.model-not-ready" {
			last = &ev
		}
		return true
	})
	if err != nil || last == nil {
		return DoctorCheck{}, false
	}
	// Both lists are [ham, spam].
	details, limit := last.Lists["details"], last.Lists["limit"]
	if len(details) != 2 || len(limit) != 2 {
		return DoctorCheck{}, false
	}
	var n [4]uint64
	for i, v := range [...]string{details[0], limit[0], details[1], limit[1]} {
		if n[i], err = strconv.ParseUint(v, 10, 64); err != nil {
			return DoctorCheck{}, false
		}
	}
	return DoctorCheck{Name: "stalwart spam classifier", Status: "ok",
		Message: fmt.Sprintf("Stalwart's spam classifier is still learning: %d of %d ham and %d of %d spam samples", n[0], n[1], n[2], n[3])}, true
}

func logHasEvent(path, name string) (found bool, err error) {
	err = scanLogEvents(path, []string{name}, func(_ stalwartlog.Event, complete bool) bool {
		found = complete
		return !found
	})
	return found, err
}

// scanLogEvents calls fn in file order until it returns false. A recognized
// header with a malformed body is passed with complete=false: classifier
// status must still supersede an older record, but login checks ignore it.
func scanLogEvents(path string, names []string, fn func(ev stalwartlog.Event, complete bool) bool) error {
	f, err := os.Open(path) // #nosec G304 -- operator-configured Stalwart log path
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	type eventMarker struct {
		name string
		text []byte
	}
	markers := make([]eventMarker, len(names))
	for i, name := range names {
		markers[i] = eventMarker{name: name, text: []byte("(" + name + ")")}
	}
	r := bufio.NewReaderSize(f, 64*1024)
	discard := false
	for {
		line, prefix, err := r.ReadLine()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		// Oversized records must not hide later events or let their tail
		// masquerade as a separate event.
		if discard || prefix {
			discard = prefix
			continue
		}
		for _, marker := range markers {
			start := bytes.Index(line, marker.text)
			if start < 0 {
				continue
			}
			end := start + len(marker.text)
			if end < len(line) && line[end] != ' ' {
				continue
			}
			ev, complete := stalwartlog.Parse(string(line))
			if !complete {
				var ok bool
				ev, ok = stalwartlog.Parse(string(line[:end]))
				if !ok {
					continue
				}
			}
			if ev.Name != marker.name {
				continue
			}
			if !fn(ev, complete) {
				return nil
			}
			break
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

// stalwartDoctorAPI is what doctor asks Stalwart: whose session it is, the
// setup steps, read only, and one spam classification.
type stalwartDoctorAPI interface {
	stalwartsetup.API
	SessionAccount(context.Context) (string, error)
	ClassifySpam(context.Context, stalwartapi.SpamProbe) (stalwartapi.SpamProbeResult, error)
}

// stalwartSettingsDoctorChecks reports CSM's API key and each setup step,
// read-only. It logs in with the key when Stalwart accepts it, else with an
// admin login from the environment.
func stalwartSettingsDoctorChecks(ctx context.Context, getenv func(string) string, newAPI func(url, user, password string) stalwartDoctorAPI, newKeyAPI func(url, key string) stalwartDoctorAPI, checkListener func(url string) error, sc config.StalwartConfig, in stalwartsetup.Inputs) (result []DoctorCheck) {
	user, password := getenv("STALWART_USER"), getenv("STALWART_PASSWORD")
	var key string
	redact := func(s string) string { return stalwartapi.Redact(stalwartapi.Redact(s, user, password), "", key) }
	defer func() {
		for i := range result {
			result[i].Name = redact(result[i].Name)
			result[i].Message = redact(result[i].Message)
			result[i].Fix = redact(result[i].Fix)
		}
	}()
	if err := checkListener(sc.APIURL); err != nil {
		var checks []DoctorCheck
		// A missing key is worth reporting even while Stalwart is down.
		if _, statErr := os.Lstat(sc.APIKeyFile); sc.APIKeyFile != "" && stalwartapi.LocalURL(sc.APIURL) && errors.Is(statErr, fs.ErrNotExist) {
			checks = append(checks, stalwartNoKeyCheck(sc.APIKeyFile))
		}
		return append(checks, DoctorCheck{Name: "stalwart settings", Status: "warn",
			Message: "Not checked; CSM sends no login to " + sc.APIURL + ": " + err.Error(),
			Fix:     "start Stalwart, or find what else listens on its admin port"})
	}
	in.LocalAPI = stalwartapi.LocalURL(sc.APIURL)
	if !in.LocalAPI {
		in.LockManaged = false
		in.LockedPorts = nil
	}

	keyCheck := DoctorCheck{Name: "stalwart API key", Status: "ok",
		Message: "Not checked; Stalwart's API address is not on this host, and CSM's key works only from this host"}
	var api stalwartDoctorAPI
	// The key works only from this host, so it is never sent anywhere else.
	if in.LocalAPI {
		var keyAPI stalwartDoctorAPI
		var account string
		var err error
		key, account, err = stalwartKeyAccount(ctx, sc.APIKeyFile, sc.APIURL, func(ctx context.Context, url, secret string) (string, error) {
			keyAPI = newKeyAPI(url, secret)
			return keyAPI.SessionAccount(ctx)
		})
		switch {
		case err == nil:
			api, in.KeyAccount = keyAPI, account
			keyCheck.Message = "Stalwart accepts CSM's API key"
		case errors.Is(err, stalwartapi.ErrNoKeyFile):
			keyCheck = stalwartNoKeyCheck(sc.APIKeyFile)
		case key == "" && errors.Is(err, fs.ErrPermission):
			keyCheck = DoctorCheck{Name: keyCheck.Name, Status: "warn",
				Message: "Not checked; only root can read CSM's API key at " + sc.APIKeyFile,
				Fix:     "run csm doctor as root"}
		case key == "":
			keyCheck = DoctorCheck{Name: keyCheck.Name, Status: "fail", Message: err.Error()}
		case errors.Is(err, stalwartapi.ErrUnauthorized), errors.Is(err, stalwartapi.ErrForbidden):
			keyCheck = DoctorCheck{Name: keyCheck.Name, Status: "fail", Message: "Stalwart refused CSM's API key", Fix: "run csm stalwart setup"}
		default:
			keyCheck = DoctorCheck{Name: keyCheck.Name, Status: "warn", Message: "Could not check CSM's API key: " + err.Error()}
		}
	}
	checks := []DoctorCheck{keyCheck}

	fix := "run csm stalwart setup"
	if api == nil {
		if user == "" || password == "" {
			message := "Not checked; set STALWART_USER and STALWART_PASSWORD to a Stalwart admin login to check Stalwart's settings"
			if in.LocalAPI {
				message = "Not checked; run csm stalwart setup, or set STALWART_USER and STALWART_PASSWORD to a Stalwart admin login"
			}
			return append(checks, DoctorCheck{Name: "stalwart settings", Status: "ok", Message: message})
		}
		api = newAPI(sc.APIURL, user, password)
		fix = "check stalwart.api_url and the admin login"
	}
	plan, err := stalwartsetup.Inspect(ctx, api, in)
	if err != nil {
		return append(checks, DoctorCheck{Name: "stalwart settings", Status: "warn",
			Message: "Cannot read Stalwart's settings at " + sc.APIURL + ": " + err.Error(), Fix: fix})
	}
	checks = append(checks, stalwartStepChecks(plan)...)
	// A filter that is off, or in an unknown state, may make no lookups.
	for _, st := range plan.Steps {
		if st.Name != "spam filter" || st.State == stalwartsetup.Warn {
			continue
		}
		res, err := api.ClassifySpam(ctx, stalwartapi.BlocklistProbe)
		checks = append(checks, stalwartBlocklistCheck(res, err, redact))
		// In observe mode the daemon does not write the list to Stalwart.
		if !plan.AddressListOn || in.Observe {
			continue
		}
		if err != nil {
			checks = append(checks, DoctorCheck{Name: "stalwart address list match", Status: "warn",
				Message: "Could not test whether Stalwart scores senders on CSM's address list: " + stalwartDiagnosticText(redact(err.Error()), 512)})
			continue
		}
		checks = append(checks, stalwartAddressListCheck(res))
	}
	return checks
}

func stalwartNoKeyCheck(path string) DoctorCheck {
	return DoctorCheck{Name: "stalwart API key", Status: "warn",
		Message: "CSM has no API key at " + path + ", so it cannot suspend mailboxes or lift Stalwart's bans",
		Fix:     "run csm stalwart setup"}
}

// stalwartBlocklistCheck reads Stalwart's verdict on one test message, which
// it neither delivers nor learns from. Through a resolver the blocklists
// refuse, such as a public one, the matched rules include ones named
// *_BLOCKED. The verdict and score are ignored: the test sender fails SPF and
// DMARC.
func stalwartBlocklistCheck(res stalwartapi.SpamProbeResult, err error, redact func(string) string) DoctorCheck {
	if err != nil {
		return DoctorCheck{Name: "stalwart blocklists", Status: "warn", Message: "Could not test Stalwart's DNS blocklists: " + stalwartDiagnosticText(redact(err.Error()), 512)}
	}
	var blocked []string
	for _, tag := range res.Tags {
		if strings.Contains(tag, "_BLOCKED") {
			// Bound terminal output, not detection: every tag before the
			// first blocked one is still examined.
			if len(blocked) == 8 {
				blocked = append(blocked, "...")
				break
			}
			blocked = append(blocked, stalwartDiagnosticText(redact(tag), 96))
		}
	}
	if len(blocked) == 0 {
		return DoctorCheck{Name: "stalwart blocklists", Status: "ok", Message: "Stalwart's DNS blocklists answer"}
	}
	return DoctorCheck{Name: "stalwart blocklists", Status: "warn",
		Message: "Stalwart's DNS blocklists refuse this server's resolver (" + strings.Join(blocked, ", ") + "), so they add nothing to spam scores",
		Fix:     "point Stalwart at a local recursive resolver, then restart Stalwart"}
}

// stalwartAddressListCheck reports whether the test message, sent from the
// address the daemon keeps on CSM's list, matched the list's canary tag.
func stalwartAddressListCheck(res stalwartapi.SpamProbeResult) DoctorCheck {
	if slices.Contains(res.Tags, ipmap.Canary.Name) {
		return DoctorCheck{Name: "stalwart address list match", Status: "ok", Message: "Stalwart scores senders on CSM's address list"}
	}
	return DoctorCheck{Name: "stalwart address list match", Status: "warn",
		Message: "Stalwart did not match CSM's test sender to CSM's address list, so listed senders get no extra spam score",
		Fix:     "the CSM daemon writes the list within 10 minutes of csm stalwart setup, so run csm doctor again after that; if it still warns, check the daemon's stalwart_address_list finding and run csm stalwart setup only when that finding says to"}
}

// stalwartDiagnosticText escapes terminal controls and bounds server text.
// Redaction must happen first, before escaping or truncation changes secrets.
func stalwartDiagnosticText(text string, maxBytes int) string {
	truncated := len(text) > maxBytes
	if truncated {
		text = text[:maxBytes]
	}
	quoted := strconv.QuoteToASCII(text)
	text = quoted[1 : len(quoted)-1]
	if len(text) > maxBytes {
		truncated = true
	}
	if truncated {
		text = text[:min(len(text), maxBytes-3)] + "..."
	}
	return text
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
			// The detail names what to clear by hand; setup then finishes
			// CSM's role, account and key.
			if strings.HasPrefix(s.Name, "response ") {
				c.Fix = "run csm stalwart setup"
			}
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
