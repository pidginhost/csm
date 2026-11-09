package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// cpanelScanLog serves access as the cPanel access log, with an empty session
// log, and returns the file's path.
func cpanelScanLog(t *testing.T, access []string) string {
	t.Helper()
	forceCPanelPlatform(t)
	dir := t.TempDir()
	files := map[string]string{
		"/usr/local/cpanel/logs/access_log":  filepath.Join(dir, "access_log"),
		"/usr/local/cpanel/logs/session_log": filepath.Join(dir, "session_log"),
	}
	if err := os.WriteFile(files["/usr/local/cpanel/logs/access_log"], []byte(strings.Join(access, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files["/usr/local/cpanel/logs/session_log"], nil, 0o600); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{open: func(name string) (*os.File, error) {
		if p, ok := files[name]; ok {
			return os.Open(p)
		}
		return nil, os.ErrNotExist
	}})
	return files["/usr/local/cpanel/logs/access_log"]
}

// lineRef is the reference of access[index] in the file written from access.
func lineRef(t *testing.T, path string, access []string, index int) alert.Observation {
	t.Helper()
	offset := 0
	for _, line := range access[:index] {
		offset += len(line) + 1
	}
	return syslogTestRef(t, path, int64(offset), access[index])
}

func oneScanFinding(t *testing.T, findings []alert.Finding, check string) alert.Finding {
	t.Helper()
	var out []alert.Finding
	for _, f := range findings {
		if f.Check == check {
			out = append(out, f)
		}
	}
	if len(out) != 1 {
		t.Fatalf("%s findings %+v, want one", check, out)
	}
	return out[0]
}

func wantScanObservation(t *testing.T, f alert.Finding, producer admission.ProducerID, ref alert.Observation, at time.Time) {
	t.Helper()
	o := f.Observation
	if o.Producer != string(producer) || o.Stream != ref.Stream || o.Cursor != ref.Cursor || !o.ObservedAt.Equal(at) || o.ObservedAt.Location() != time.UTC {
		t.Fatalf("%s observation %+v, want %s %+v logged at %v", f.Check, o, producer, ref, at)
	}
}

func cpanelStamp(second int) string { return fmt.Sprintf("11/09/2026:12:00:%02d", second) }

func cpanelTime(second int) time.Time { return time.Date(2026, 11, 9, 12, 0, second, 0, time.UTC) }

// cpsrvd writes the connecting peer first and stamps its own time; the scan
// reads both the way the realtime path does.
func TestCpanelAccessLogTime(t *testing.T) {
	for line, want := range map[string]time.Time{
		staleSessionAccessLine("203.0.113.9", "-", cpanelStamp(7), "/execute/Themes/list", "401"):       cpanelTime(7),
		staleSessionAccessLine("203.0.113.9", "a [b] c", cpanelStamp(8), "/execute/Themes/list", "401"): cpanelTime(8),
		`203.0.113.9 - - [09/Nov/2026:12:00:09 +0000] "GET / HTTP/1.1" 401 0`:                           {},
		`203.0.113.9 - - [11/09/2026:12:00:10 -0000]`:                                                   {},
		"": {},
	} {
		got, ok := cpanelAccessLogTime(line)
		if ok != !want.IsZero() || !got.Equal(want) {
			t.Errorf("time of %q is %v (%v), want %v", line, got, ok, want)
		}
	}
}

// An API failure finding names the newest failure of its address that
// cpsrvd stamped, read as the peer, in the access log's file stream. A time
// a client wrote into the user field loses to the address's real newer
// records, and a record dated after the scan is never the observation:
// admission would refuse a root from the future.
func TestAPIAuthFailureScanNamesItsNewestFailure(t *testing.T) {
	var access []string
	for i := 0; i < apiFailThreshold; i++ {
		access = append(access, staleSessionAccessLine("203.0.113.9", "-", cpanelStamp(i), "/execute/Themes/list", "401"))
	}
	access = append(access,
		staleSessionAccessLine("203.0.113.9", "-", "bad", "/execute/Themes/list", "401"),
		staleSessionAccessLine("203.0.113.9", `x [11/09/2026:11:00:00 -0000] "y`, cpanelStamp(30), "/execute/Themes/list", "401"),
		staleSessionAccessLine("203.0.113.9", "-", "12/31/2099:00:00:00", "/execute/Themes/list", "401"),
		staleSessionAccessLine("203.0.113.9", "-", cpanelStamp(40), "/execute/Themes/list", "200"))
	path := cpanelScanLog(t, access)
	f := oneScanFinding(t, CheckAPIAuthFailures(context.Background(), &config.Config{}, nil), "api_auth_failure")
	if f.Attribution != admission.AttributionPeer {
		t.Fatalf("attribution %s, want peer", f.Attribution)
	}
	wantScanObservation(t, f, ProducerCpanelScan, lineRef(t, path, access, apiFailThreshold-1), cpanelTime(apiFailThreshold-1))
	again := oneScanFinding(t, CheckAPIAuthFailures(context.Background(), &config.Config{}, nil), "api_auth_failure")
	if again.Observation != f.Observation {
		t.Fatalf("a re-read named %+v, then %+v", f.Observation, again.Observation)
	}
}

// A webmail brute-force finding names the newest counted login attempt.
func TestWebmailScanNamesItsNewestAttempt(t *testing.T) {
	var access []string
	for i := 0; i <= webmailThreshold; i++ {
		access = append(access, fmt.Sprintf(`203.0.113.5 - - [%s -0000] "POST /login/?session=2096 HTTP/1.1" 200 0 "-" "Mozilla/5.0" "-" "-" 2096`, cpanelStamp(i)))
	}
	access = append(access, fmt.Sprintf(`203.0.113.5 - - [%s -0000] "GET /webmail HTTP/1.1" 200 0 "-" "Mozilla/5.0" "-" "-" 2096`, cpanelStamp(50)))
	path := cpanelScanLog(t, access)
	f := oneScanFinding(t, CheckWebmailLogins(context.Background(), &config.Config{}, nil), "webmail_bruteforce")
	if f.Attribution != admission.AttributionPeer {
		t.Fatalf("attribution %s, want peer", f.Attribution)
	}
	wantScanObservation(t, f, ProducerCpanelScan, lineRef(t, path, access, webmailThreshold), cpanelTime(webmailThreshold))
}

// A threshold met only by records without a log time is still reported, but
// names no observation admission could mint from.
func TestCpanelScanWithoutALogTimeNamesNothing(t *testing.T) {
	var access []string
	for i := 0; i < apiFailThreshold; i++ {
		access = append(access, staleSessionAccessLine("203.0.113.9", "-", "bad", "/execute/Themes/list", "401"))
	}
	cpanelScanLog(t, access)
	if f := oneScanFinding(t, CheckAPIAuthFailures(context.Background(), &config.Config{}, nil), "api_auth_failure"); f.Observation != (alert.Observation{}) {
		t.Fatalf("observation %+v, want none", f.Observation)
	}
}

// cpanelUTCStamp formats t as cpsrvd writes its time, without the zone.
func cpanelUTCStamp(t time.Time) string { return t.UTC().Format("01/02/2006:15:04:05") }

// A client chooses the user field. Only one complete cpsrvd parse dates a
// record: a user field holding its own timestamp followed by a quote makes
// the record ambiguous, whatever follows it, and a malformed suffix has no
// time. Ordinary users with spaces, brackets, quotes or addresses still parse.
func TestCpanelAccessLogTimeRejectsAmbiguousUserTime(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	server := now.Add(-admission.RootFreshness - time.Hour)
	forged := "[" + cpanelUTCStamp(now) + " -0000]"
	line := func(user string) string {
		return staleSessionAccessLine("203.0.113.9", user, cpanelUTCStamp(server), "/execute/Themes/list", "401")
	}
	for name, user := range map[string]string{
		"dash":            "-",
		"brackets":        "a [b] c",
		"spaces":          "user name",
		"quote":           `x "y`,
		"address":         "2001:db8::1 198.51.100.7",
		"date only":       "x " + forged + " y",
		"bracketed stamp": "[" + cpanelUTCStamp(now) + "]",
	} {
		if got, ok := cpanelAccessLogTime(line(user)); !ok || !got.Equal(server) {
			t.Errorf("%s: time %v (%v), want the server time %v", name, got, ok, server)
		}
	}
	for name, l := range map[string]string{
		"forged quote":         line("x " + forged + ` "y`),
		"forged full suffix":   line("x " + forged + ` "GET /execute/Themes/list HTTP/1.1" 401 0 "https://example.com:2083/" "Mozilla/5.0" "-" "-" 2083 y`),
		"forged at start":      line(forged + ` "GET / HTTP/1.1" 401 0`),
		"forged tab":           line("x " + forged + "\t\"y"),
		"forged address":       line("198.51.100.7 - x " + forged + ` "y`),
		"forged unspaced":      line("x" + forged + ` "y`),
		"no request":           "203.0.113.9 - - [" + cpanelUTCStamp(server) + " -0000]",
		"bad method":           "203.0.113.9 - - [" + cpanelUTCStamp(server) + ` -0000] "G(T / HTTP/1.1" 401 0`,
		"bad version":          "203.0.113.9 - - [" + cpanelUTCStamp(server) + ` -0000] "GET / HTTP/1" 401 0 "-" "-" "-" "-" 2083`,
		"bad status":           "203.0.113.9 - - [" + cpanelUTCStamp(server) + ` -0000] "GET / HTTP/1.1" 4x1 0`,
		"bad size":             "203.0.113.9 - - [" + cpanelUTCStamp(server) + ` -0000] "GET / HTTP/1.1" 401 x`,
		"trailing junk":        line("-") + " junk",
		"fifth quoted field":   "203.0.113.9 - - [" + cpanelUTCStamp(server) + ` -0000] "GET / HTTP/1.1" 401 0 "-" "-" "-" "-" "-" 2083`,
		"port out of range":    "203.0.113.9 - - [" + cpanelUTCStamp(server) + ` -0000] "GET / HTTP/1.1" 401 0 "-" "-" "-" "-" 70000`,
		"peer not an address":  strings.Replace(line("-"), "203.0.113.9", "host.example", 1),
		"ident not cpsrvd's":   strings.Replace(line("-"), "203.0.113.9 - ", "203.0.113.9 x ", 1),
		"apache date":          `203.0.113.9 - - [09/Nov/2026:12:00:09 +0000] "GET / HTTP/1.1" 401 0`,
		"unterminated request": "203.0.113.9 - - [" + cpanelUTCStamp(server) + ` -0000] "GET / HTTP/1.1 401 0`,
	} {
		if got, ok := cpanelAccessLogTime(l); ok || !got.IsZero() {
			t.Errorf("%s: %q dated %v (%v), want no time", name, l, got, ok)
		}
	}
	for _, l := range []string{
		"203.0.113.9 - - [" + cpanelUTCStamp(server) + ` -0000] "POST /login/ HTTP/1.1" 200 1234 2095`,
		"203.0.113.9 - - [" + cpanelUTCStamp(server) + ` -0000] "GET /scripts2/listaccts HTTP/1.1" 200 0 "-" "curl/8.4.0" "host.example.com:2087"`,
		"2001:db8::9 - - [" + cpanelUTCStamp(server) + ` -0000] "POST /login/?session=2096 HTTP/1.1" 200 0 "-" "Mozilla/5.0" "-" "-" 2096`,
		"203.0.113.9 - - [" + cpanelUTCStamp(server) + ` -0000] "GET / HTTP/2" 401 -`,
	} {
		if got, ok := cpanelAccessLogTime(l); !ok || !got.Equal(server) {
			t.Errorf("%q dated %v (%v), want the server time %v", l, got, ok, server)
		}
	}
}

// A current-looking timestamp in the user field of old records cannot
// refresh their evidence. The legacy finding is unchanged, but it names no
// observation. The same old records with an ordinary user mint evidence that
// admission refuses as stale; current records mint and assess.
func TestCpanelScanCannotRefreshOldEvidenceWithUserTime(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	old := now.Add(-admission.RootFreshness - time.Hour)
	forgedUser := "198.51.100.7 x [" + cpanelUTCStamp(now) + ` -0000] "GET /execute/Themes/list HTTP/1.1" 401 0 "-" "-" "-" "-" 2083 y`
	reg, err := admission.NewRegistry(AdmissionPolicy)
	if err != nil {
		t.Fatal(err)
	}
	var producer *admission.Producer
	for _, p := range ProducerTable() {
		registered, regErr := reg.Register(p.Spec)
		if regErr != nil {
			t.Fatal(regErr)
		}
		if p.Spec.ID == ProducerCpanelScan {
			producer = registered
		}
	}
	scans := map[string]struct {
		threshold int
		line      func(user string, at time.Time) string
		run       func() []alert.Finding
	}{
		"api_auth_failure": {apiFailThreshold, func(user string, at time.Time) string {
			return staleSessionAccessLine("203.0.113.9", user, cpanelUTCStamp(at), "/execute/Themes/list", "401")
		}, func() []alert.Finding { return CheckAPIAuthFailures(context.Background(), &config.Config{}, nil) }},
		"webmail_bruteforce": {webmailThreshold, func(user string, at time.Time) string {
			return fmt.Sprintf(`203.0.113.9 - %s [%s -0000] "POST /login/?session=2096 HTTP/1.1" 200 0 "-" "Mozilla/5.0" "-" "-" 2096`, user, cpanelUTCStamp(at))
		}, func() []alert.Finding { return CheckWebmailLogins(context.Background(), &config.Config{}, nil) }},
	}
	for check, scan := range scans {
		t.Run(check, func(t *testing.T) {
			finding := func(user string, start time.Time) alert.Finding {
				var access []string
				for i := 0; i < scan.threshold; i++ {
					access = append(access, scan.line(user, start.Add(time.Duration(i)*time.Second)))
				}
				cpanelScanLog(t, access)
				return oneScanFinding(t, scan.run(), check)
			}
			mint := func(f alert.Finding) (admission.Evidence, admission.Target) {
				t.Helper()
				id, in, err := AdmissionEvidence(f)
				if err != nil || id != ProducerCpanelScan {
					t.Fatalf("evidence from %+v: producer %s, error %v", f, id, err)
				}
				e, err := producer.Mint(in)
				if err != nil {
					t.Fatalf("mint %+v: %v", in, err)
				}
				return e, in.Target
			}

			forged := finding(forgedUser, old)
			ordinary := finding("-", old)
			if forged.SourceIP != "203.0.113.9" || forged.SourceIP != ordinary.SourceIP || forged.Severity != ordinary.Severity ||
				forged.Message != ordinary.Message || forged.Attribution != ordinary.Attribution {
				t.Fatalf("forged user changed the legacy finding: %+v, ordinary %+v", forged, ordinary)
			}
			if forged.Observation != (alert.Observation{}) {
				t.Fatalf("a forged current time in the user field supplied observation %+v", forged.Observation)
			}
			if _, _, err := AdmissionEvidence(forged); admission.CauseOf(err) != admission.CauseNoObservation {
				t.Fatalf("forged finding: %v, want the no-observation cause", err)
			}

			e, target := mint(ordinary)
			if reason, ok := admission.ReasonOf(func() error { _, err := admission.Assess(target, []admission.Evidence{e}, now); return err }()); !ok || reason != admission.ReasonStale {
				t.Fatalf("old records assessed with reason %v (%v), want stale", reason, ok)
			}

			current := finding("-", now.Add(-time.Minute))
			e, target = mint(current)
			if _, err := admission.Assess(target, []admission.Evidence{e}, now); err != nil {
				t.Fatalf("current records: %v", err)
			}
		})
	}
}
