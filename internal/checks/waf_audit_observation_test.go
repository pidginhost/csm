package checks

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

const (
	auditTimedJSON   = `{"transaction":{"client_ip":"203.0.113.50","time_stamp":"Sun Nov  8 08:40:00 2026","response":{"http_code":403}}}`
	auditUntimedJSON = `{"transaction":{"client_ip":"203.0.113.50","response":{"http_code":403}}}`
	auditErrorDenial = `[Sun Nov 08 08:40:00.000000 2026] [security2:error] [pid 123] [client 203.0.113.50:5555] ModSecurity: Access denied with code 403`
)

// A WAF finding names the newest denial of its address that the audit log
// recorded, by the record the address was read from: the index, JSON or
// error-log line, or the A-section header of a serial transaction. The time
// is the one the server wrote, and a re-read after a restart names it alike.
func TestModSecAuditScanNamesItsNewestDenial(t *testing.T) {
	v3 := `example.com 2001:db8::50 - [08/Nov/2026:08:40:00 +0000] "GET / HTTP/1.1" 403 199 - "probe" tx - /audit/tx 0 1234 md5:0123456789abcdef0123456789abcdef`
	utc := time.Date(2026, 11, 8, 8, 40, 0, 0, time.UTC)
	local := time.Date(2026, 11, 8, 8, 40, 0, 0, time.Local)
	repeat := func(line string) string { return strings.Repeat(line+"\n", 25) }
	var serial strings.Builder
	for i := 0; i < 25; i++ {
		serial.WriteString(serialTransaction(fmt.Sprintf("a1b2c3%02d", i), "203.0.113.50", 403))
	}
	for name, tc := range map[string]struct {
		content, anchor, client string
		at                      time.Time
		errorLog                bool
	}{
		"index v2": {repeat(modsecIndexLine("example.com", "203.0.113.50", "GET /x HTTP/1.1", "probe", 403)) + modsecIndexLine("example.com", "203.0.113.50", "GET / HTTP/1.1", "probe", 200) + "\n",
			modsecIndexLine("example.com", "203.0.113.50", "GET /x HTTP/1.1", "probe", 403), "203.0.113.50", utc, false},
		"index v3": {repeat(v3), v3, "2001:db8::50", utc, false},
		"JSON":     {repeat(auditTimedJSON) + strings.Replace(auditTimedJSON, "403", "200", 1) + "\n", auditTimedJSON, "203.0.113.50", local, false},
		"serial": {serial.String() + serialTransaction("b2c3d4e5", "203.0.113.50", 200),
			"[03/Sep/2026:10:00:00 +0000] a1b2c324 203.0.113.50 54321 198.51.100.1 443", "203.0.113.50", time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC), false},
		"error log": {repeat(auditErrorDenial) + strings.Replace(auditErrorDenial, "Access denied", "Warning. Matched", 1) + "\n", auditErrorDenial, "203.0.113.50", local, true},
	} {
		t.Run(name, func(t *testing.T) {
			path := setupSerialAuditLog(t, tc.content)
			cfg := &config.Config{}
			if tc.errorLog {
				cfg.ModSecErrorLog = "/var/log/httpd/modsec_audit.log"
			}
			f := oneScanFinding(t, CheckModSecAuditLog(context.Background(), cfg, nil), "waf_attack_blocked")
			if f.SourceIP != tc.client || f.Attribution != admission.AttributionHTTPPeer {
				t.Fatalf("finding for %s read as %s, want %s as the HTTP peer", f.SourceIP, f.Attribution, tc.client)
			}
			wantScanObservation(t, f, ProducerModSecAuditScan, syslogTestRef(t, path, int64(strings.LastIndex(tc.content, tc.anchor)), tc.anchor), tc.at)
			modsecAuditReader.Lock()
			modsecAuditReader.path = ""
			modsecAuditReader.Unlock()
			again := oneScanFinding(t, CheckModSecAuditLog(context.Background(), cfg, nil), "waf_attack_blocked")
			if again.Observation != f.Observation {
				t.Fatalf("a restarted reader named %+v, then %+v", f.Observation, again.Observation)
			}
		})
	}
}

// A denial dated after the scan is never the newest record: the address keeps
// naming its newest denial admission can accept.
func TestModSecAuditScanSkipsAFutureDenial(t *testing.T) {
	denial := modsecIndexLine("example.com", "203.0.113.50", "GET /x HTTP/1.1", "probe", 403)
	future := strings.Replace(denial, "08/Nov/2026:08:40:00.000000", "08/Nov/2099:08:40:00.000000", 1)
	content := strings.Repeat(denial+"\n", 25) + future + "\n"
	path := setupSerialAuditLog(t, content)
	f := oneScanFinding(t, CheckModSecAuditLog(context.Background(), &config.Config{}, nil), "waf_attack_blocked")
	wantScanObservation(t, f, ProducerModSecAuditScan, syslogTestRef(t, path, int64(strings.LastIndex(content, denial+"\n")), denial), time.Date(2026, 11, 8, 8, 40, 0, 0, time.UTC))
}

// A threshold met only by denials without a recorded time is still reported,
// but names no observation admission could mint from.
func TestModSecAuditScanWithoutARecordTimeNamesNothing(t *testing.T) {
	setupSerialAuditLog(t, strings.Repeat(auditUntimedJSON+"\n", 25))
	if f := oneScanFinding(t, CheckModSecAuditLog(context.Background(), &config.Config{}, nil), "waf_attack_blocked"); f.Observation != (alert.Observation{}) {
		t.Fatalf("observation %+v, want none", f.Observation)
	}
}

// Timestamp metadata cannot suppress denials that the legacy reader counted.
func TestModSecAuditJSONInvalidTimeKeepsDenials(t *testing.T) {
	for _, stamp := range []string{`123`, `true`, `{}`, `[]`, `null`, `"invalid"`} {
		t.Run(stamp, func(t *testing.T) {
			line := fmt.Sprintf(`{"transaction":{"client_ip":"203.0.113.50","time_stamp":%s,"response":{"http_code":403}}}`, stamp)
			setupSerialAuditLog(t, strings.Repeat(line+"\n", 25))
			f := oneScanFinding(t, CheckModSecAuditLog(context.Background(), &config.Config{}, nil), "waf_attack_blocked")
			if f.SourceIP != "203.0.113.50" || f.Observation != (alert.Observation{}) ||
				f.Message != "WAF blocking high-volume attacker: 203.0.113.50 (25 blocked requests)" {
				t.Fatalf("invalid timestamp changed the legacy finding: %+v", f)
			}
		})
	}
}

// Cached and replayed reads select the same last eligible denial as the scan
// clock advances, including timestamps less than a second ahead of the scan.
func TestModSecAuditFutureRecordBecomesEligible(t *testing.T) {
	for _, ahead := range []time.Duration{500 * time.Millisecond, 2 * time.Second} {
		t.Run(ahead.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				now := time.Now().UTC()
				lineAt := func(at time.Time) string {
					return strings.Replace(modsecIndexLine("example.test", "203.0.113.50", "GET / HTTP/1.1", "probe", 403),
						"08/Nov/2026:08:40:00.000000 +0000", at.Format("02/Jan/2006:15:04:05.000000 -0700"), 1)
				}
				past, future := lineAt(now.Add(-time.Minute)), lineAt(now.Add(ahead))
				content := strings.Repeat(past+"\n", 25) + future + "\n"
				path := setupSerialAuditLog(t, content)
				read := func() alert.Finding {
					return oneScanFinding(t, CheckModSecAuditLog(context.Background(), &config.Config{}, nil), "waf_attack_blocked")
				}
				first := read()
				wantScanObservation(t, first, ProducerModSecAuditScan, syslogTestRef(t, path, int64(24*(len(past)+1)), past), now.Add(-time.Minute))
				time.Sleep(ahead) // Virtual time; no wall-clock deadline.
				later := read()
				wantScanObservation(t, later, ProducerModSecAuditScan, syslogTestRef(t, path, int64(25*(len(past)+1)), future), now.Add(ahead))
				modsecAuditReader.Lock()
				modsecAuditReader.path = ""
				modsecAuditReader.Unlock()
				if replay := read(); replay.Observation != later.Observation || replay.Message != first.Message {
					t.Fatalf("cached and replayed scans differ: cached %+v, replay %+v", later, replay)
				}
			})
		})
	}
}

// A partial timestamp prefix is not a server-written A header, although the
// legacy client parser can still count its denial.
func TestModSecAuditMalformedHeaderHasNoObservation(t *testing.T) {
	for _, stamp := range []string{
		"[03/Sep/2026:10:00:00 +0000",
		"[03/Sep/2026:10:00:00 +2400]",
		"[03/Sep/2026:10:00:00 +0060]",
	} {
		t.Run(stamp, func(t *testing.T) {
			content := strings.ReplaceAll(serialTransaction("a1b2c3d4", "203.0.113.50", 403), "[03/Sep/2026:10:00:00 +0000]", stamp)
			setupSerialAuditLog(t, strings.Repeat(content, 25))
			f := oneScanFinding(t, CheckModSecAuditLog(context.Background(), &config.Config{}, nil), "waf_attack_blocked")
			if f.Observation != (alert.Observation{}) {
				t.Fatalf("malformed timestamp supplied an observation: %+v", f.Observation)
			}
		})
	}
}

func TestModSecAuditInvalidIndexZoneKeepsDenials(t *testing.T) {
	for _, zone := range []string{"+2400", "-2400", "+0060", "-0060"} {
		t.Run(zone, func(t *testing.T) {
			line := strings.Replace(modsecIndexLine("example.test", "203.0.113.50", "GET / HTTP/1.1", "probe", 403), "+0000", zone, 1)
			setupSerialAuditLog(t, strings.Repeat(line+"\n", 25))
			f := oneScanFinding(t, CheckModSecAuditLog(context.Background(), &config.Config{}, nil), "waf_attack_blocked")
			if f.Observation != (alert.Observation{}) {
				t.Fatalf("invalid zone supplied an observation: %+v", f.Observation)
			}
		})
	}
}

func TestModSecAuditIncompleteHeaderHasNoObservation(t *testing.T) {
	for name, tail := range map[string]string{
		"missing server":      "54321",
		"missing port":        "54321 198.51.100.1",
		"invalid client port": "bad 198.51.100.1 443",
		"invalid server":      "54321 not-an-address 443",
		"invalid server port": "54321 198.51.100.1 bad",
		"overflowing port":    "54321 198.51.100.1 65536",
		"trailing data":       "54321 198.51.100.1 443 extra",
	} {
		t.Run(name, func(t *testing.T) {
			content := strings.Replace(serialTransaction("a1b2c3d4", "203.0.113.50", 403), "54321 198.51.100.1 443", tail, 1)
			var p modsecAuditParser
			feedSerialLines(&p, 0, content)
			if p.blocked["203.0.113.50"] != 1 || len(p.newestAt(time.Now())) != 0 {
				t.Fatalf("incomplete header changed counts or supplied evidence: %v, %+v", p.blocked, p.newestAt(time.Now()))
			}
		})
	}
}

func TestModSecAuditHeaderTimeValidatesAddresses(t *testing.T) {
	for _, address := range []string{"203.0.113.50", "2001:db8::50", "[2001:db8::50]"} {
		header := "[03/Sep/2026:10:00:00.123456 +0530] tx " + address + " 54321 [2001:db8::1] 443"
		want := time.Date(2026, 9, 3, 4, 30, 0, 123456000, time.UTC)
		if got := modsecAuditHeaderTime(header); !got.Equal(want) {
			t.Fatalf("valid header time %v, want %v", got, want)
		}
	}
	for _, address := range []string{"[2001:db8::50", "2001:db8::50]", "[[2001:db8::50]]"} {
		for _, header := range []string{
			"[03/Sep/2026:10:00:00 +0000] tx " + address + " 54321 198.51.100.1 443",
			"[03/Sep/2026:10:00:00 +0000] tx 203.0.113.50 54321 " + address + " 443",
		} {
			if got := modsecAuditHeaderTime(header); !got.IsZero() {
				t.Errorf("malformed address in %q supplied time %v", header, got)
			}
		}
	}
}

// A clock adjustment changes eligibility, but log position still chooses
// the last counted denial rather than the greatest timestamp.
func TestModSecAuditNewestTracksScanClock(t *testing.T) {
	at := time.Date(2026, 11, 8, 8, 40, 0, 0, time.Local)
	var p modsecAuditParser
	for i, minute := range []int{0, 2, 1} {
		line := strings.Replace(auditTimedJSON, "08:40:00", at.Add(time.Duration(minute)*time.Minute).Format("15:04:05"), 1)
		p.feed(syslogRecord{text: line, offset: int64(i) * 100}, false)
	}
	for _, tc := range []struct {
		elapsed time.Duration
		offset  int64
	}{
		{3 * time.Minute, 200},
		{time.Minute, 200},
		{time.Minute - time.Nanosecond, 0},
		{-time.Nanosecond, -1},
		{3 * time.Minute, 200},
	} {
		newest := p.newestAt(at.Add(tc.elapsed))
		n, ok := newest["203.0.113.50"]
		if tc.offset < 0 {
			if len(newest) != 0 {
				t.Fatalf("before all records, named %+v", newest)
			}
		} else if !ok || len(newest) != 1 || n.offset != tc.offset {
			t.Fatalf("scan at %v named %+v, want offset %d", tc.elapsed, newest, tc.offset)
		}
		if p.blocked["203.0.113.50"] != 3 {
			t.Fatalf("scan clock changed denial counts: %v", p.blocked)
		}
	}
}

// The newest denial leaves the recent window with its line; later denials
// without a time keep the count but name no observation.
func TestModSecAuditNewestAgesOutWithItsRecord(t *testing.T) {
	var p modsecAuditParser
	p.feed(syslogRecord{text: auditTimedJSON, offset: 0}, false)
	for i := 1; i < modsecAuditTailLines; i++ {
		p.feed(syslogRecord{text: auditUntimedJSON, offset: int64(i) * 100}, false)
	}
	if r, ok := p.newestAt(time.Now())["203.0.113.50"]; !ok || r.offset != 0 || r.at.IsZero() {
		t.Fatalf("newest %+v (%v), want the timed denial at offset 0", r, ok)
	}
	p.feed(syslogRecord{text: auditUntimedJSON, offset: int64(modsecAuditTailLines) * 100}, false)
	if r, ok := p.newestAt(time.Now())["203.0.113.50"]; ok || p.blocked["203.0.113.50"] != modsecAuditTailLines {
		t.Fatalf("newest %+v with %d denials, want none once the timed denial left the window", r, p.blocked["203.0.113.50"])
	}
}

// Evicting an older denial of an address keeps the address's newer record.
// The newest leaves only with its own line; untimed denials keep counting,
// and another address is evicted on its own line.
func TestModSecAuditNewestSurvivesOlderEviction(t *testing.T) {
	newerJSON := strings.Replace(auditTimedJSON, "08:40:00", "08:41:00", 1)
	otherJSON := strings.Replace(auditTimedJSON, "203.0.113.50", "203.0.113.51", 1)
	var p modsecAuditParser
	feed := func(text string) { p.feed(syslogRecord{text: text, offset: p.line * 100}, false) }
	feed(auditTimedJSON) // line 1
	feed(otherJSON)      // line 2
	feed(newerJSON)      // line 3
	for p.line < modsecAuditTailLines {
		feed(auditUntimedJSON)
	}
	newer := time.Date(2026, 11, 8, 8, 41, 0, 0, time.Local)
	wantNewer := func(when string, count int) {
		t.Helper()
		n, ok := p.newestAt(time.Now())["203.0.113.50"]
		if !ok || n.offset != 200 || n.cursor != alert.RecordCursor(200, newerJSON) || !n.at.Equal(newer) || n.line != 3 {
			t.Fatalf("%s: newest %+v (%v), want the later denial at offset 200", when, n, ok)
		}
		if got := p.blocked["203.0.113.50"]; got != count {
			t.Fatalf("%s: %d denials, want %d in the window", when, got, count)
		}
	}
	wantNewer("before eviction", modsecAuditTailLines-1)

	feed(auditUntimedJSON) // line 4001 evicts line 1
	wantNewer("older evicted", modsecAuditTailLines-1)
	if n, ok := p.newestAt(time.Now())["203.0.113.51"]; !ok || n.offset != 100 || p.blocked["203.0.113.51"] != 1 {
		t.Fatalf("other address %+v (%v) with %d denials, want its own record kept", n, ok, p.blocked["203.0.113.51"])
	}

	feed(auditUntimedJSON) // line 4002 evicts line 2
	if n, ok := p.newestAt(time.Now())["203.0.113.51"]; ok || p.blocked["203.0.113.51"] != 0 {
		t.Fatalf("other address %+v with %d denials after its line left", n, p.blocked["203.0.113.51"])
	}
	wantNewer("other evicted", modsecAuditTailLines)

	feed(auditUntimedJSON) // line 4003 evicts line 3
	if n, ok := p.newestAt(time.Now())["203.0.113.50"]; ok || p.blocked["203.0.113.50"] != modsecAuditTailLines {
		t.Fatalf("newest %+v with %d denials, want none named once the later line left", n, p.blocked["203.0.113.50"])
	}
}

// feedSerialLines feeds text line by line at its byte offsets and returns
// the parser line and offset each line was fed at.
func feedSerialLines(p *modsecAuditParser, offset int64, text string) (lines []int64, offsets []int64) {
	for _, l := range strings.SplitAfter(text, "\n") {
		if l == "" {
			continue
		}
		p.feed(syslogRecord{text: trimLogLineEnding(l), offset: offset}, false)
		lines, offsets = append(lines, p.line), append(offsets, offset)
		offset += int64(len(l))
	}
	return lines, offsets
}

// A serial transaction is counted at its A boundary line and named by its A
// header, at the header's offset and bytes. It leaves the window with the
// boundary line. A Z that arrives once the boundary has left the window
// creates neither a count nor an observation.
func TestModSecAuditSerialObservationExpiresAtBoundary(t *testing.T) {
	const header = "[03/Sep/2026:10:00:00 +0000] a1b2c3d4 203.0.113.50 54321 198.51.100.1 443"
	var p modsecAuditParser
	feedSerialLines(&p, 0, "lead\nlead\n")
	lines, offsets := feedSerialLines(&p, 10, serialTransaction("a1b2c3d4", "203.0.113.50", 403))
	boundary := lines[0]
	n, ok := p.newestAt(time.Now())["203.0.113.50"]
	if !ok || n.line != boundary || n.offset != offsets[1] || n.cursor != alert.RecordCursor(offsets[1], header) ||
		!n.at.Equal(time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)) || p.blocked["203.0.113.50"] != 1 {
		t.Fatalf("newest %+v (%v), want the A header at %d counted at boundary line %d", n, ok, offsets[1], boundary)
	}
	for p.line < boundary+modsecAuditTailLines-1 {
		p.feed(syslogRecord{text: "filler", offset: 0}, false)
	}
	if _, ok := p.newestAt(time.Now())["203.0.113.50"]; !ok || p.blocked["203.0.113.50"] != 1 {
		t.Fatalf("at line %d the denial left early: %+v", p.line, p.newestAt(time.Now()))
	}
	p.feed(syslogRecord{text: "filler", offset: 0}, false)
	if n, ok := p.newestAt(time.Now())["203.0.113.50"]; ok || p.blocked["203.0.113.50"] != 0 {
		t.Fatalf("at line %d (boundary %d + window) newest %+v with %d denials, want none", p.line, boundary, n, p.blocked["203.0.113.50"])
	}

	for _, late := range []int64{modsecAuditTailLines, modsecAuditTailLines + 1} {
		t.Run(fmt.Sprintf("Z at boundary+%d", late), func(t *testing.T) {
			var p modsecAuditParser
			lines, _ := feedSerialLines(&p, 0, "--b2c3d4e5-A--\n"+strings.Replace(header, "a1b2c3d4", "b2c3d4e5", 1)+"\n--b2c3d4e5-F--\nHTTP/1.1 403\n")
			boundary := lines[0]
			for p.line < boundary+late-1 {
				p.feed(syslogRecord{text: "X-Filler: body", offset: 0}, false)
			}
			p.feed(syslogRecord{text: "--b2c3d4e5-Z--", offset: 0}, false)
			if p.line != boundary+late {
				t.Fatalf("Z fed at line %d, want %d", p.line, boundary+late)
			}
			if n, ok := p.newestAt(time.Now())["203.0.113.50"]; ok || p.blocked["203.0.113.50"] != 0 {
				t.Fatalf("Z at boundary+%d counted %d denials and named %+v, want nothing", late, p.blocked["203.0.113.50"], n)
			}
		})
	}
}

// A transaction split across reads is named by its original A header. A reset
// reader replaying unchanged bytes names it alike; the same bytes in another
// file are another stream.
func TestModSecAuditSplitTransactionKeepsHeaderRef(t *testing.T) {
	const header = "[03/Sep/2026:10:00:00 +0000] a1b2c3d4 203.0.113.50 54321 198.51.100.1 443"
	full := serialTransaction("a1b2c3d4", "203.0.113.50", 403)
	cut := strings.Index(full, header) + len(header) + 1
	path := setupSerialAuditLog(t, full[:cut])
	reset := func() {
		modsecAuditReader.Lock()
		modsecAuditReader.path = ""
		modsecAuditReader.Unlock()
	}
	reset()
	t.Cleanup(reset)
	read := func(when string) scanRecord {
		t.Helper()
		counts, newest, ok := readModSecDenials(context.Background(), "/var/log/httpd/modsec_audit.log", false)
		if !ok {
			t.Fatalf("%s: read failed", when)
		}
		if counts["203.0.113.50"] != 1 {
			t.Fatalf("%s: counts %v, want one denial", when, counts)
		}
		return newest["203.0.113.50"]
	}
	if counts, newest, _ := readModSecDenials(context.Background(), "/var/log/httpd/modsec_audit.log", false); len(counts) != 0 || len(newest) != 0 {
		t.Fatalf("an open transaction counted %v named %v", counts, newest)
	}
	w, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(full[cut:]); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	offset := int64(strings.Index(full, header))
	first := read("split")
	if want := syslogTestRef(t, path, offset, header); first.stream != want.Stream || first.cursor != want.Cursor ||
		!first.at.Equal(time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("split transaction named %+v, want the A header %+v", first, want)
	}
	reset()
	if again := read("replay"); again != first {
		t.Fatalf("a reset reader named %+v, first %+v", again, first)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(full), 0o600); err != nil {
		t.Fatal(err)
	}
	rotated := read("rotated")
	if want := syslogTestRef(t, path, offset, header); rotated.stream == first.stream || rotated.stream != want.Stream || rotated.cursor != first.cursor {
		t.Fatalf("rotated file named %+v, first %+v, want stream %s", rotated, first, want.Stream)
	}
}
