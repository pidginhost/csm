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
	"github.com/pidginhost/csm/internal/platform"
)

// The access log the sighting tests serve as the platform's.
const sightingAccessLog = "/var/log/httpd/access_log"

// sightingLogs serves each named log from its own file, on a cPanel host
// whose access log is sightingAccessLog, and returns the files' paths.
func sightingLogs(t *testing.T, logs map[string]string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	paths := map[string]string{}
	i := 0
	for name, content := range logs {
		path := filepath.Join(dir, fmt.Sprintf("log%d", i))
		i++
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		paths[name] = path
	}
	// The auth log's path depends on the OS family.
	if p, ok := paths["/var/log/secure"]; ok {
		paths["/var/log/auth.log"] = p
	}
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if p, ok := paths[name]; ok {
				return os.Open(p)
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			if p, ok := paths[name]; ok {
				return os.Stat(p)
			}
			return nil, os.ErrNotExist
		},
		readFile: os.ReadFile,
	})
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{Panel: ptrPanel(platform.PanelCPanel), AccessLogPaths: []string{sightingAccessLog}})
	return paths
}

// listIPs lists each address in a test threat feed and returns the scan
// config using that state.
func listIPs(t *testing.T, ips ...string) *config.Config {
	t.Helper()
	statePath := t.TempDir()
	t.Cleanup(SetGlobalThreatDBForTest(statePath))
	for _, ip := range ips {
		GetThreatDB().badIPs[ip] = "test-feed"
	}
	return &config.Config{StatePath: statePath}
}

// sightingLines are one recent record of each log the scan reads, all at at,
// naming ip the way that log's parser reads it.
func sightingLines(ip string, at time.Time) map[string]string {
	syslog := at.Format(time.Stamp)
	return map[string]string{
		"SSH login":      syslog + " host sshd[1]: Accepted publickey for root from " + ip + " port 22 ssh2",
		"HTTP request":   ip + ` - - [` + at.Format("02/Jan/2006:15:04:05 -0700") + `] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"`,
		"mail login":     syslog + " host dovecot: imap-login: Aborted login (auth failed, 1 attempts in 2 secs): user=<a@example.com>, method=PLAIN, rip=" + ip + ", lip=192.0.2.1, TLS",
		"cPanel access":  staleSessionAccessLine(ip, "-", at.UTC().Format("01/02/2006:15:04:05"), "/execute/Themes/list", "401"),
		"SMTP auth fail": at.Format(time.DateTime) + " dovecot_login authenticator failed for (helo) [" + ip + "]:5432: 535 Incorrect authentication data (set_id=a@example.com)",
		// log_timezone: Exim writes its zone after the time.
		"SMTP zoned": at.In(time.FixedZone("", 5*3600+1800)).Format(time.DateTime) + " +0530 dovecot_login authenticator failed for (helo) [" + ip + "]:5432: 535 Incorrect authentication data (set_id=a@example.com)",
	}
}

// logPathFor is the path the scan reads each kind of sighting from.
var logPathFor = map[string]string{
	"SSH login":      "/var/log/secure",
	"HTTP request":   sightingAccessLog,
	"mail login":     "/var/log/maillog",
	"cPanel access":  reputationWHMAccessLog,
	"SMTP auth fail": reputationEximMainlog,
	"SMTP zoned":     reputationEximMainlog,
}

// A reputation finding names the local record that put its address in the
// scan: the record its log's parser read the address from, at the time the
// log wrote it, as derived evidence that mints.
func TestReputationFindingNamesItsSighting(t *testing.T) {
	at := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	for kind, line := range sightingLines("203.0.113.60", at) {
		t.Run(kind, func(t *testing.T) {
			cfg := listIPs(t, "203.0.113.60")
			cfg.MailLogs.File = "/var/log/maillog"
			paths := sightingLogs(t, map[string]string{logPathFor[kind]: line + "\n"})
			f := reputationFindingFor(t, CheckIPReputation(context.Background(), cfg, nil), "203.0.113.60")
			want := syslogTestRef(t, paths[logPathFor[kind]], 0, line)
			o := f.Observation
			if f.Attribution != admission.AttributionDerived || o.Producer != string(ProducerReputationScan) ||
				o.Stream != want.Stream || o.Cursor != want.Cursor || !o.ObservedAt.Equal(at) || o.ObservedAt.Location() != time.UTC {
				t.Fatalf("finding %s read as %s named %+v, want derived %+v at %v", f.SourceIP, f.Attribution, o, want, at)
			}
			if _, _, err := mintScanFinding(t, f); err != nil {
				t.Fatalf("mint: %v", err)
			}
		})
	}
}

// Only a record its log's parser reads, dated by the server within the last
// day, is a sighting. The legacy finding stays without one, and mints nothing.
func TestReputationSightingMustBeARecentParsedRecord(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	for name, tc := range map[string]struct {
		path, line string
		trusted    bool
	}{
		"older than a day":           {"/var/log/secure", now.Add(-25*time.Hour).Format(time.Stamp) + " host sshd[1]: Accepted publickey for root from 203.0.113.61 port 22 ssh2", false},
		"dated after the scan":       {"/var/log/secure", now.Add(time.Hour).Format(time.RFC3339) + " host sshd[1]: Accepted publickey for root from 203.0.113.61 port 22 ssh2", false},
		"unparsed access line":       {sightingAccessLog, "203.0.113.61 garbage", false},
		"dated but unparsed request": {sightingAccessLog, `203.0.113.61 - - [` + now.Add(-time.Minute).Format("02/Jan/2006:15:04:05 -0700") + `] "GET / HTTP/1.1 200 100`, false},
		"trusted proxy peer":         {sightingAccessLog, `203.0.113.61 - - [` + now.Add(-time.Minute).Format("02/Jan/2006:15:04:05 -0700") + `] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"`, true},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := listIPs(t, "203.0.113.61")
			if tc.trusted {
				cfg.WebServer.TrustedProxies = []string{"203.0.113.61"}
			}
			sightingLogs(t, map[string]string{tc.path: tc.line + "\n"})
			f := reputationFindingFor(t, CheckIPReputation(context.Background(), cfg, nil), "203.0.113.61")
			if f.Observation != (alert.Observation{}) || f.Attribution != admission.AttributionUnknown {
				t.Fatalf("finding named %+v read as %s, want no sighting", f.Observation, f.Attribution)
			}
			if _, _, err := mintScanFinding(t, f); admission.CauseOf(err) != admission.CauseNoObservation {
				t.Fatalf("mint: %v, want the no-observation cause", err)
			}
		})
	}
}

// The scan keeps an address's strongest sighting; the finding names that
// sighting's record, and the newest record of it.
func TestReputationNamesTheStrongestSightingsNewestRecord(t *testing.T) {
	at := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	lines := sightingLines("203.0.113.62", at)
	older := sightingLines("203.0.113.62", at.Add(-time.Minute))
	// The weaker surface's record is the newest of all: it still loses.
	newer := sightingLines("203.0.113.62", at.Add(time.Minute))
	cfg := listIPs(t, "203.0.113.62")
	cfg.MailLogs.File = "/var/log/maillog"
	paths := sightingLogs(t, map[string]string{
		sightingAccessLog:  newer["HTTP request"] + "\n",
		"/var/log/maillog": older["mail login"] + "\n" + lines["mail login"] + "\n",
	})
	f := reputationFindingFor(t, CheckIPReputation(context.Background(), cfg, nil), "203.0.113.62")
	want := syslogTestRef(t, paths["/var/log/maillog"], int64(len(older["mail login"])+1), lines["mail login"])
	if f.Severity != alert.Critical || f.Observation.Stream != want.Stream || f.Observation.Cursor != want.Cursor {
		t.Fatalf("finding %s named %+v, want the newest mail login record %+v", f.Severity, f.Observation, want)
	}
}

// A rescan of unchanged logs names the same sighting and mints the same
// evidence.
func TestReputationSightingIsStableAcrossScans(t *testing.T) {
	at := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	cfg := listIPs(t, "203.0.113.63")
	sightingLogs(t, map[string]string{"/var/log/secure": sightingLines("203.0.113.63", at)["SSH login"] + "\n"})
	first := reputationFindingFor(t, CheckIPReputation(context.Background(), cfg, nil), "203.0.113.63")
	again := reputationFindingFor(t, CheckIPReputation(context.Background(), cfg, nil), "203.0.113.63")
	a, _, err := mintScanFinding(t, first)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := mintScanFinding(t, again)
	if err != nil {
		t.Fatal(err)
	}
	if first.Observation != again.Observation || a.ID() != b.ID() {
		t.Fatalf("rescan named %+v then %+v", first.Observation, again.Observation)
	}
}

// sshAt is an sshd login of ip that sshd dated at.
func sshAt(at time.Time, ip string) string {
	return at.Format(time.RFC3339Nano) + " host sshd[1]: Accepted publickey for root from " + ip + " port 22 ssh2"
}

// recordOffsets is where each of lines starts in a file holding them one
// per line.
func recordOffsets(lines []string) []int64 {
	offsets := make([]int64, len(lines))
	var off int64
	for i, l := range lines {
		offsets[i] = off
		off += int64(len(l)) + 1
	}
	return offsets
}

// A sighting is dated within the day before the scan and never after it,
// to the nanosecond; the address stays in the scan either way.
func TestReputationSightingScanTimeBoundaries(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		ip       string
		at       time.Time
		sighting bool
	}{
		{"203.0.113.70", now.Add(-reputationSightingWindow), true},
		{"203.0.113.71", now.Add(-reputationSightingWindow - time.Nanosecond), false},
		{"203.0.113.72", now, true},
		{"203.0.113.73", now.Add(time.Nanosecond), false},
		{"203.0.113.74", now.Add(500 * time.Millisecond), false},
	}
	var lines []string
	for _, c := range cases {
		lines = append(lines, sshAt(c.at, c.ip))
	}
	paths := sightingLogs(t, map[string]string{"/var/log/secure": strings.Join(lines, "\n") + "\n"})
	offsets := recordOffsets(lines)
	ips, records := collectRecentSightings(&config.Config{}, now)
	for i, c := range cases {
		if ips[c.ip] != "SSH login" {
			t.Errorf("%s collected as %q, want SSH login", c.ip, ips[c.ip])
		}
		r, ok := records[c.ip]
		if ok != c.sighting {
			t.Errorf("%s at %v: sighting %v, want %v", c.ip, c.at, ok, c.sighting)
			continue
		}
		if !ok {
			continue
		}
		want := syslogTestRef(t, paths["/var/log/secure"], offsets[i], lines[i])
		if o := r.observation(ProducerReputationScan); o.Stream != want.Stream || o.Cursor != want.Cursor || !o.ObservedAt.Equal(c.at) {
			t.Errorf("%s sighting %+v, want %+v at %v", c.ip, o, want, c.at)
		}
	}
}

// An Exim sighting carries the instant Exim wrote: fractional seconds, its
// zone when logged, and local time otherwise. A time its zone makes stale,
// or an invalid zone, leaves the address without a sighting; a prefix the
// RCPT parser rejects, including any zone Exim cannot write, contributes no
// address at all.
func TestReputationEximSightingUsesFullServerTime(t *testing.T) {
	// The server zone comes from the scan clock; time.Local stays untouched,
	// since other goroutines read it.
	server := time.FixedZone("local", 2*3600)
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC).In(server)
	recent := now.Add(-10*time.Minute + 125*time.Millisecond)
	ist, mst, line := time.FixedZone("ist", 5*3600+1800), time.FixedZone("mst", -7*3600), time.FixedZone("lint", 14*3600)
	authFail := func(prefix, ip string) string {
		return prefix + " dovecot_login authenticator failed for (helo) [" + ip + "]:5432: 535 Incorrect authentication data (set_id=a@example.com)"
	}
	rcpt := func(prefix, ip string) string {
		return prefix + " H=(helo) [" + ip + "]:1 F=<a@example.com> rejected RCPT <b@example.net>: Sender verify failed"
	}
	const zoned, local = "2006-01-02 15:04:05.000 -0700", "2006-01-02 15:04:05.000"
	cases := []struct {
		name, ip, line string
		collected      bool
		at             time.Time // zero: no sighting
	}{
		{"auth positive zone", "203.0.113.100", authFail(recent.In(ist).Format(zoned), "203.0.113.100"), true, recent},
		{"auth negative zone", "203.0.113.101", authFail(recent.In(mst).Format(zoned), "203.0.113.101"), true, recent},
		{"auth local fraction", "203.0.113.102", authFail(recent.In(server).Format(local), "203.0.113.102"), true, recent},
		{"rcpt positive zone", "203.0.113.103", rcpt(recent.In(ist).Format(zoned), "203.0.113.103"), true, recent},
		{"rcpt local fraction", "203.0.113.104", rcpt(recent.In(server).Format(local), "203.0.113.104"), true, recent},
		// Read in the local zone, this day-old record would look recent.
		{"auth stale in its zone", "203.0.113.105", authFail(now.Add(-25*time.Hour).In(line).Format(zoned), "203.0.113.105"), true, time.Time{}},
		{"auth invalid zone", "203.0.113.106", authFail(recent.In(server).Format(time.DateTime)+" +9999", "203.0.113.106"), true, time.Time{}},
		{"rcpt out-of-range zone", "203.0.113.107", rcpt(recent.In(server).Format(time.DateTime)+" +2400", "203.0.113.107"), false, time.Time{}},
		{"rcpt invalid zone", "203.0.113.108", rcpt(recent.In(server).Format(time.DateTime)+" +9999", "203.0.113.108"), false, time.Time{}},
	}
	var lines []string
	for _, c := range cases {
		lines = append(lines, c.line)
	}
	paths := sightingLogs(t, map[string]string{reputationEximMainlog: strings.Join(lines, "\n") + "\n"})
	offsets := recordOffsets(lines)
	ips, records := collectRecentSightings(&config.Config{}, now)
	for i, c := range cases {
		if got := ips[c.ip] == "SMTP auth failure"; got != c.collected {
			t.Errorf("%s: collected as %q, want collected %v", c.name, ips[c.ip], c.collected)
		}
		r, ok := records[c.ip]
		if ok != !c.at.IsZero() {
			t.Errorf("%s: sighting %v at %v, want one %v", c.name, ok, r.at, !c.at.IsZero())
			continue
		}
		if !ok {
			continue
		}
		want := syslogTestRef(t, paths[reputationEximMainlog], offsets[i], lines[i])
		if o := r.observation(ProducerReputationScan); o.Stream != want.Stream || o.Cursor != want.Cursor || !o.ObservedAt.Equal(c.at) {
			t.Errorf("%s: sighting %+v, want %+v at %v", c.name, o, want, c.at.UTC())
		}
	}
}

// Each surface names the address its own parser reads and the time its
// server wrote. Client text holding another listed address or a recent
// time never makes a sighting; a record without a server time, an unfinished
// line or a trusted proxy's own request keeps the legacy finding, which
// mints nothing.
func TestReputationSightingUsesOnlyItsParsersPeerAndTime(t *testing.T) {
	const injected = "198.51.100.99"
	now := time.Now()
	server := now.Add(-2 * time.Hour).Truncate(time.Second)
	forgedApache := "[" + now.Add(-time.Minute).Format("02/Jan/2006:15:04:05 -0700") + "]"
	forgedCpanel := "[" + cpanelUTCStamp(now.Add(-time.Minute)) + " -0000]"
	syslog := server.Format(time.Stamp)
	access := func(ip, user string) string {
		return ip + ` - ` + user + ` [` + server.Format("02/Jan/2006:15:04:05 -0700") + `] "GET /?ip=` + injected + `&t=` + forgedApache + ` HTTP/1.1" 200 100 "` + injected + `" "Mozilla/5.0 ` + forgedApache + `"`
	}
	for _, tc := range []struct {
		name, path, line, ip, surface string
		trusted                       []string
		sighting                      bool
		unfinished                    bool
	}{
		{name: "SSH user", path: "/var/log/secure", ip: "203.0.113.80", surface: "SSH login", sighting: true,
			line: syslog + " host sshd[1]: Accepted password for " + injected + " from 203.0.113.80 port 22 ssh2"},
		{name: "mail login user", path: "/var/log/maillog", ip: "203.0.113.81", surface: reputationViaMailLogin, sighting: true,
			line: syslog + " host dovecot: imap-login: Aborted login (auth failed, 1 attempts in 2 secs): user=<x rip=" + injected + ", " + now.Format(time.RFC3339) + ">, method=PLAIN, rip=203.0.113.81, lip=192.0.2.1, TLS"},
		{name: "HTTP user and request", path: sightingAccessLog, ip: "203.0.113.82", surface: "HTTP request", sighting: true,
			line: access("203.0.113.82", injected)},
		{name: "cPanel user", path: reputationWHMAccessLog, ip: "203.0.113.83", surface: "cPanel/WHM access", sighting: true,
			line: staleSessionAccessLine("203.0.113.83", injected+" x", cpanelUTCStamp(server), "/execute/x?"+injected, "401")},
		{name: "cPanel ambiguous stamp", path: reputationWHMAccessLog, ip: "203.0.113.84", surface: "cPanel/WHM access",
			line: staleSessionAccessLine("203.0.113.84", "x "+forgedCpanel+` "y`, cpanelUTCStamp(server), "/execute/x", "401")},
		{name: "SMTP HELO and login", path: reputationEximMainlog, ip: "203.0.113.85", surface: "SMTP auth failure", sighting: true,
			line: server.Format(time.DateTime) + " dovecot_login authenticator failed for (" + injected + " [" + injected + "]:1) [203.0.113.85]:5432: 535 Incorrect authentication data (set_id=" + injected + " " + now.Format(time.DateTime) + ")"},
		{name: "SMTP RCPT", path: reputationEximMainlog, ip: "203.0.113.86", surface: "SMTP auth failure", sighting: true,
			line: server.Format(time.DateTime) + " H=(" + injected + ") [203.0.113.86]:1 F=<a@example.com> rejected RCPT <\"" + injected + " [" + injected + "]\"@example.net>: Sender verify failed"},
		{name: "no server time", path: "/var/log/secure", ip: "203.0.113.87", surface: "SSH login",
			line: "host sshd[1]: Accepted publickey for root from 203.0.113.87 port 22 ssh2"},
		{name: "unfinished line", path: "/var/log/secure", ip: "203.0.113.88", surface: "SSH login", unfinished: true,
			line: syslog + " host sshd[1]: Accepted publickey for root from 203.0.113.88 port 22 ssh2"},
		{name: "trusted IPv4", path: sightingAccessLog, ip: "203.0.113.89", surface: "HTTP request", trusted: []string{"203.0.113.89"},
			line: access("203.0.113.89", "-")},
		{name: "trusted CIDR", path: sightingAccessLog, ip: "203.0.113.90", surface: "HTTP request", trusted: []string{"203.0.113.0/24"},
			line: access("203.0.113.90", "-")},
		{name: "trusted IPv6", path: sightingAccessLog, ip: "2001:db8::90", surface: "HTTP request", trusted: []string{"2001:db8::/32"},
			line: access("2001:db8::90", "-")},
		{name: "trusted cPanel peer", path: reputationWHMAccessLog, ip: "203.0.113.91", surface: "cPanel/WHM access", trusted: []string{"203.0.113.91"},
			line: staleSessionAccessLine("203.0.113.91", "-", cpanelUTCStamp(server), "/execute/x", "401")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := listIPs(t, tc.ip, injected)
			cfg.MailLogs.File = "/var/log/maillog"
			cfg.WebServer.TrustedProxies = tc.trusted
			content := tc.line + "\n"
			if tc.unfinished {
				content = tc.line
			}
			paths := sightingLogs(t, map[string]string{tc.path: content})
			findings := CheckIPReputation(context.Background(), cfg, nil)
			for _, f := range findings {
				if f.Check == "ip_reputation" && f.SourceIP == injected {
					t.Fatalf("client text put %s in the scan: %+v", injected, f)
				}
			}
			f := reputationFindingFor(t, findings, tc.ip)
			if f.Severity != reputationSightingSeverity(tc.surface) {
				t.Fatalf("severity %s, want the %s surface's %s", f.Severity, tc.surface, reputationSightingSeverity(tc.surface))
			}
			if !tc.sighting {
				if f.Observation != (alert.Observation{}) || f.Attribution != admission.AttributionUnknown {
					t.Fatalf("finding named %+v read as %s, want no sighting", f.Observation, f.Attribution)
				}
				if _, _, err := mintScanFinding(t, f); admission.CauseOf(err) != admission.CauseNoObservation {
					t.Fatalf("mint: %v, want the no-observation cause", err)
				}
				return
			}
			want := syslogTestRef(t, paths[tc.path], 0, tc.line)
			o := f.Observation
			if f.Attribution != admission.AttributionDerived || o.Stream != want.Stream || o.Cursor != want.Cursor || !o.ObservedAt.Equal(server) {
				t.Fatalf("finding read as %s named %+v, want derived %+v at the server time %v", f.Attribution, o, want, server.UTC())
			}
		})
	}
}

// The sighting never changes which surface the legacy scan keeps: the
// strongest, the first of equal strength in scan order. Only that surface
// names a record, its newest; an unusable stronger record leaves none.
// Loopback and infrastructure addresses stay out.
func TestReputationSightingPreservesLegacySurfaceChoice(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	at := func(ago time.Duration) time.Time { return now.Add(-ago) }
	const a, b, c, d, e, f, g = "203.0.113.110", "203.0.113.111", "203.0.113.112", "203.0.113.113", "203.0.113.114", "203.0.113.115", "203.0.113.116"
	ssh := []string{
		sightingLines(a, at(5*time.Minute))["SSH login"],
		sightingLines(a, at(20*time.Minute))["SSH login"],
		sightingLines(b, at(5*time.Minute))["SSH login"],
		sightingLines("127.0.0.1", at(time.Minute))["SSH login"],
		sightingLines("192.0.2.50", at(time.Minute))["SSH login"],
	}
	httpLog := []string{
		sightingLines(c, at(3*time.Minute))["HTTP request"],
		sightingLines(d, at(2*time.Minute))["HTTP request"],
		sightingLines(e, at(2*time.Minute))["HTTP request"],
	}
	mail := []string{
		sightingLines(b, at(time.Minute))["mail login"],
		sightingLines(d, at(25*time.Hour))["mail login"],
		strings.TrimPrefix(sightingLines(e, at(time.Minute))["mail login"], now.Add(-time.Minute).Format(time.Stamp)+" "),
	}
	cpanel := []string{
		sightingLines(c, at(time.Minute))["cPanel access"],
		sightingLines(f, at(time.Minute))["cPanel access"],
	}
	exim := []string{sightingLines(g, at(time.Minute))["SMTP auth fail"]}
	join := func(lines []string) string { return strings.Join(lines, "\n") + "\n" }
	cfg := &config.Config{InfraIPs: []string{"192.0.2.50"}}
	cfg.MailLogs.File = "/var/log/maillog"
	paths := sightingLogs(t, map[string]string{
		"/var/log/secure":      join(ssh),
		sightingAccessLog:      join(httpLog),
		"/var/log/maillog":     join(mail),
		reputationWHMAccessLog: join(cpanel),
		reputationEximMainlog:  join(exim),
	})
	wantIPs := map[string]string{
		a: "SSH login", b: "SSH login", c: "HTTP request", d: reputationViaMailLogin,
		e: reputationViaMailLogin, f: "cPanel/WHM access", g: "SMTP auth failure",
	}
	type rec struct {
		path  string
		lines []string
		i     int
		at    time.Time
	}
	wantRecords := map[string]rec{
		a: {"/var/log/secure", ssh, 0, at(5 * time.Minute)},
		b: {"/var/log/secure", ssh, 2, at(5 * time.Minute)},
		c: {sightingAccessLog, httpLog, 0, at(3 * time.Minute)},
		f: {reputationWHMAccessLog, cpanel, 1, at(time.Minute)},
		g: {reputationEximMainlog, exim, 0, at(time.Minute)},
	}
	ips, records := collectRecentSightings(cfg, now)
	if fmt.Sprint(ips) != fmt.Sprint(wantIPs) {
		t.Fatalf("sightings collected %v, want %v", ips, wantIPs)
	}
	if legacy := collectRecentIPs(cfg); fmt.Sprint(legacy) != fmt.Sprint(wantIPs) {
		t.Fatalf("legacy collection %v, want %v", legacy, wantIPs)
	}
	if len(records) != len(wantRecords) {
		t.Fatalf("records for %d addresses, want %d: %+v", len(records), len(wantRecords), records)
	}
	for ip, w := range wantRecords {
		r, ok := records[ip]
		want := syslogTestRef(t, paths[w.path], recordOffsets(w.lines)[w.i], w.lines[w.i])
		if o := r.observation(ProducerReputationScan); !ok || o.Stream != want.Stream || o.Cursor != want.Cursor || !o.ObservedAt.Equal(w.at) {
			t.Errorf("%s (%s) named %+v, want %+v at %v", ip, ips[ip], o, want, w.at)
		}
	}
	// The stronger surface keeps the finding's severity although it names
	// no sighting.
	listed := listIPs(t, d)
	listed.MailLogs.File = "/var/log/maillog"
	if fd := reputationFindingFor(t, CheckIPReputation(context.Background(), listed, nil), d); fd.Severity != alert.Critical || fd.Observation != (alert.Observation{}) {
		t.Fatalf("finding %s named %+v, want critical with no sighting", fd.Severity, fd.Observation)
	}
}
