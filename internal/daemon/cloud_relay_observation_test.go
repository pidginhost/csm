package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/eximlog"
	"github.com/pidginhost/csm/internal/store"
)

const retroTestPTR = "ec2-203-0-113-20.eu-west-3.compute.amazonaws.com"

// retroSends is a volume burst of cloud sends for one account, the last one
// from another address, a minute apart.
func retroSends(base time.Time) []string {
	var lines []string
	for i := 0; i < 18; i++ {
		ip := "203.0.113.20"
		if i == 17 {
			ip = "203.0.113.21"
		}
		lines = append(lines, eximLine(base.Add(time.Duration(i)*time.Minute), "info@example.com", retroTestPTR, ip, "subject"))
	}
	return lines
}

// offsetOf is where lines[i] starts in a file holding lines one per line.
func offsetOf(lines []string, i int) int64 {
	var offset int64
	for _, l := range lines[:i] {
		offset += int64(len(l)) + 1
	}
	return offset
}

// The retrospective Exim scan names its finding by the newest counted send:
// the mainlog record at its offset and bytes, at the time Exim wrote it, read
// as the session peer the finding names.
func TestEximHistoryScanNamesItsNewestSend(t *testing.T) {
	base := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	lines := retroSends(base)
	path := writeEximFixture(t, lines)
	withGlobalStore(t, func(*store.DB) {
		findings := ScanEximHistoryForCloudRelay(&config.Config{}, path, time.Now(), 24*time.Hour)
		if len(findings) != 1 {
			t.Fatalf("findings %+v, want one", findings)
		}
		f := findings[0]
		if f.SourceIP != "203.0.113.21" || f.Attribution != admission.AttributionPeer {
			t.Fatalf("finding names %s read as %s, want the newest send's peer", f.SourceIP, f.Attribution)
		}
		want := recordRef(t, path, offsetOf(lines, 17), lines[17])
		o := f.Observation
		if o.Producer != string(checks.ProducerEximHistory) || !sameRef(o, want) ||
			!o.ObservedAt.Equal(base.Add(17*time.Minute)) || o.ObservedAt.Location() != time.UTC {
			t.Fatalf("observation %+v, want exim_history %+v logged at %v", o, want, base.Add(17*time.Minute))
		}
	})
}

// The realtime watcher and the retrospective scan read the same mainlog
// record; both name it alike, so independence counts it once. The watcher
// reads the lines through its own framing, with either line ending.
func TestEximHistoryScanAndWatcherNameOneRecord(t *testing.T) {
	for _, tc := range []struct{ name, eol string }{{"LF", "\n"}, {"CRLF", "\r\n"}} {
		t.Run(tc.name, func(t *testing.T) {
			lines := retroSends(time.Now().Add(-2 * time.Hour).Truncate(time.Second))
			path := filepath.Join(t.TempDir(), "exim_mainlog")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			ch := make(chan alert.Finding, len(lines))
			every := func(line string, _ *config.Config) []alert.Finding {
				return []alert.Finding{{Check: "fixture", Message: line}}
			}
			w, err := newObservedLogWatcher(logWatchSpec{path: path, handler: every, producer: checks.ProducerEximLog}, &config.Config{}, ch)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(w.closeFile)
			appendLog(t, path, strings.Join(lines, tc.eol)+tc.eol)
			w.readNewLines()
			read := drainObservedFindings(ch)
			if len(read) != len(lines) {
				t.Fatalf("watcher read %d records, want %d", len(read), len(lines))
			}
			var offset int64
			for i, l := range lines {
				if i >= 16 && !sameRef(read[i].Observation, recordRef(t, path, offset, l)) {
					t.Fatalf("watcher named record %d %+v, want offset %d", i, read[i].Observation, offset)
				}
				offset += int64(len(l) + len(tc.eol))
			}
			withGlobalStore(t, func(*store.DB) {
				findings := ScanEximHistoryForCloudRelay(&config.Config{}, path, time.Now(), 24*time.Hour)
				if len(findings) != 1 {
					t.Fatalf("findings %+v, want one", findings)
				}
				if !sameRef(read[17].Observation, findings[0].Observation) {
					t.Fatalf("watcher named %+v, retrospective scan %+v", read[17].Observation, findings[0].Observation)
				}
			})
		})
	}
}

// A send still being written when the scan read it has no record yet: the
// finding stays, read as the peer, but names no observation.
func TestEximHistoryScanUnfinishedSendNamesNothing(t *testing.T) {
	lines := retroSends(time.Now().Add(-2 * time.Hour).Truncate(time.Second))
	path := filepath.Join(t.TempDir(), "exim_mainlog")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	withGlobalStore(t, func(*store.DB) {
		findings := ScanEximHistoryForCloudRelay(&config.Config{}, path, time.Now(), 24*time.Hour)
		if len(findings) != 1 || findings[0].SourceIP != "203.0.113.21" || findings[0].Attribution != admission.AttributionPeer {
			t.Fatalf("findings %+v, want the legacy finding read as the peer", findings)
		}
		if findings[0].Observation != (alert.Observation{}) {
			t.Fatalf("unfinished send named %+v", findings[0].Observation)
		}
	})
}

// At the per-account event cap the current send still enters the window, so
// the finding names the address of the line the watcher observed.
func TestCloudRelayAtTheEventCapNamesTheCurrentSend(t *testing.T) {
	resetCloudRelayState()
	t.Cleanup(resetCloudRelayState)
	const user = "info@example.com"
	now := time.Now()
	w := &cloudRelayWindow{lastEvent: now}
	for range cloudRelayMaxEvents {
		w.events = append(w.events, cloudRelayEvent{at: now.Add(-time.Minute), ip: "203.0.113.30", ptr: "vm.googleusercontent.com"})
	}
	cloudRelayWindows.Store(user, w)
	findings := parseCloudRelayFinding(gceSendLine(user, "203.0.113.31.bc.googleusercontent.com", "203.0.113.31"), cloudRelayTestConfig())
	if len(findings) != 1 || findings[0].SourceIP != "203.0.113.31" {
		t.Fatalf("findings %+v, want the current send's address", findings)
	}
	if got := len(w.events); got != cloudRelayMaxEvents {
		t.Fatalf("window holds %d events, want the cap %d", got, cloudRelayMaxEvents)
	}
}

// stampedAs replaces line's leading Exim time with prefix.
func stampedAs(line, prefix string) string { return prefix + line[len(time.DateTime):] }

// The history observation carries the instant Exim wrote, read from its
// whole prefix: fractional seconds and, when logged, the zone. Counting reads
// the same time.
func TestEximHistoryObservationUsesFullServerTime(t *testing.T) {
	// The server zone comes from the scan clock; time.Local stays untouched,
	// since other goroutines read it.
	server := time.FixedZone("local", 2*3600)
	now := time.Now().In(server)
	base := now.Add(-12 * time.Hour).Truncate(time.Second)
	for _, tc := range []struct {
		name   string
		layout string
		zone   *time.Location
	}{
		{"positive zone", "2006-01-02 15:04:05.000 -0700", time.FixedZone("ist", 5*3600+1800)},
		{"negative zone", "2006-01-02 15:04:05.000 -0700", time.FixedZone("mst", -7*3600)},
		{"fraction without zone", "2006-01-02 15:04:05.000", server},
		{"zone without fraction", "2006-01-02 15:04:05 -0700", time.FixedZone("ist", 5*3600+1800)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := retroSends(base)
			var newest time.Time
			for i := range lines {
				at := base.Add(time.Duration(i)*time.Minute + 125*time.Millisecond)
				if !strings.Contains(tc.layout, ".000") {
					at = at.Truncate(time.Second)
				}
				lines[i] = stampedAs(lines[i], at.In(tc.zone).Format(tc.layout))
				newest = at
			}
			path := writeEximFixture(t, lines)
			withGlobalStore(t, func(*store.DB) {
				findings := ScanEximHistoryForCloudRelay(&config.Config{}, path, now, 48*time.Hour)
				if len(findings) != 1 || findings[0].SourceIP != "203.0.113.21" || findings[0].Attribution != admission.AttributionPeer {
					t.Fatalf("findings %+v, want one naming the newest send's peer", findings)
				}
				o := findings[0].Observation
				if !sameRef(o, recordRef(t, path, offsetOf(lines, 17), lines[17])) {
					t.Fatalf("observation %+v does not name the newest send", o)
				}
				if !o.ObservedAt.Equal(newest) || o.ObservedAt.Location() != time.UTC {
					t.Fatalf("observed at %v, want the server instant %v in UTC", o.ObservedAt, newest.UTC())
				}
			})
		})
	}
	// An explicit zone outside the offsets Exim writes dates nothing, so the
	// send is not counted and the newest dated send names itself: the peer
	// and the record always come from the same line.
	t.Run("invalid zone", func(t *testing.T) {
		lines := retroSends(base)
		lines[17] = stampedAs(lines[17], base.Add(17*time.Minute).Format(time.DateTime)+" +2400")
		path := writeEximFixture(t, lines)
		withGlobalStore(t, func(*store.DB) {
			findings := ScanEximHistoryForCloudRelay(&config.Config{}, path, now, 48*time.Hour)
			if len(findings) != 1 || findings[0].SourceIP != "203.0.113.20" || findings[0].Attribution != admission.AttributionPeer {
				t.Fatalf("findings %+v, want one naming the newest dated send's peer", findings)
			}
			if !strings.Contains(findings[0].Details, "total cloud-PTR sends (48h): 17\n") {
				t.Fatalf("undated send was counted: %s", findings[0].Details)
			}
			if !sameRef(findings[0].Observation, recordRef(t, path, offsetOf(lines, 16), lines[16])) {
				t.Fatalf("observation %+v does not name the newest dated send", findings[0].Observation)
			}
		})
	})
}

// Each account's finding names its own newest counted send, whatever the
// other account and uncounted lines in between say.
func TestEximHistoryRecordBindingAcrossAccounts(t *testing.T) {
	base := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	const a, b = "info@example.com", "sales@example.com"
	var lines []string
	newestA := -1
	for i := 0; i < 18; i++ {
		ipA, ipB := "203.0.113.20", "203.0.113.30"
		if i%2 == 1 {
			ipA, ipB = "203.0.113.21", "203.0.113.31"
		}
		if i == 17 {
			ipB = "203.0.113.40"
		}
		lines = append(lines, eximLine(base.Add(time.Duration(i)*time.Minute), a, retroTestPTR, ipA, "subject"))
		newestA = len(lines) - 1
		if i == 17 {
			// An uncounted delivery from another peer between the two
			// accounts' last sends.
			lines = append(lines, base.Add(17*time.Minute+10*time.Second).Format(time.DateTime)+
				" 1abd-0000-AB => victim@example.com R=dnslookup T=remote_smtp H=mx.example [203.0.113.50]:25")
		}
		lines = append(lines, eximLine(base.Add(time.Duration(i)*time.Minute+30*time.Second), b, retroTestPTR, ipB, "subject"))
	}
	path := filepath.Join(t.TempDir(), "exim_mainlog")
	// The file ends inside account b's last send.
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	withGlobalStore(t, func(*store.DB) {
		findings := ScanEximHistoryForCloudRelay(&config.Config{}, path, time.Now(), 24*time.Hour)
		byUser := map[string]alert.Finding{}
		for _, f := range findings {
			for _, u := range []string{a, b} {
				if strings.Contains(f.Message, u) {
					byUser[u] = f
				}
			}
		}
		if len(findings) != 2 || len(byUser) != 2 {
			t.Fatalf("findings %+v, want one per account", findings)
		}
		fa := byUser[a]
		if fa.SourceIP != eximlog.ClientIP(lines[newestA]) || fa.Attribution != admission.AttributionPeer ||
			!sameRef(fa.Observation, recordRef(t, path, offsetOf(lines, newestA), lines[newestA])) {
			t.Fatalf("account a finding %s %+v, want its last send %s", fa.SourceIP, fa.Observation, lines[newestA])
		}
		fb := byUser[b]
		if fb.SourceIP != "203.0.113.40" || fb.Observation != (alert.Observation{}) {
			t.Fatalf("account b finding %s %+v, want the unfinished send's peer and no record", fb.SourceIP, fb.Observation)
		}
	})
}

// Prefix spacing must neither hide a valid zone nor let an invalid one
// borrow local time. A send counts only when its time is readable.
func TestEximHistoryObservationZoneAfterWhitespace(t *testing.T) {
	now := time.Date(2026, 1, 2, 22, 0, 0, 0, time.UTC).In(time.FixedZone("local", 2*3600))
	base := now.Add(-12 * time.Hour)
	for _, zone := range []string{"+0530", "-0700", "+2400", "-0060"} {
		t.Run(zone, func(t *testing.T) {
			lines := retroSends(base)
			prefix := base.Add(17*time.Minute).Format(time.DateTime) + ".125  " + zone
			lines[17] = stampedAs(lines[17], prefix)
			path := writeEximFixture(t, lines)
			withGlobalStore(t, func(*store.DB) {
				findings := ScanEximHistoryForCloudRelay(&config.Config{}, path, now, 48*time.Hour)
				if zone == "+2400" || zone == "-0060" {
					if len(findings) != 1 || findings[0].SourceIP != "203.0.113.20" ||
						!strings.Contains(findings[0].Details, "total cloud-PTR sends (48h): 17\n") {
						t.Fatalf("findings %+v, want the undated send left uncounted", findings)
					}
					if o := findings[0].Observation; !sameRef(o, recordRef(t, path, offsetOf(lines, 16), lines[16])) {
						t.Fatalf("invalid zone named %+v, want the newest dated send", o)
					}
					return
				}
				if len(findings) != 1 || findings[0].SourceIP != "203.0.113.21" || findings[0].Attribution != admission.AttributionPeer ||
					!strings.Contains(findings[0].Details, "total cloud-PTR sends (48h): 18\n") {
					t.Fatalf("findings %+v, want the zoned send counted for the newest peer", findings)
				}
				o := findings[0].Observation
				want, err := time.Parse(time.DateTime+" -0700", strings.Replace(prefix, "  ", " ", 1))
				if err != nil {
					t.Fatal(err)
				}
				if !o.ObservedAt.Equal(want) || o.ObservedAt.Location() != time.UTC ||
					!sameRef(o, recordRef(t, path, offsetOf(lines, 17), lines[17])) {
					t.Fatalf("observation %+v, want the newest record at %v", o, want.UTC())
				}
			})
		})
	}
}
