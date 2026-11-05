package blockdigest

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	_ "time/tzdata"
)

// summaryStore is the persisted summary record shared by successive
// collectors, standing in for the daemon's bbolt meta key.
type summaryStore struct {
	mu    sync.Mutex
	data  []byte
	saves int
}

func (s *summaryStore) load() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.data...), nil
}

func (s *summaryStore) save(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = append([]byte(nil), b...)
	s.saves++
	return nil
}

func (s *summaryStore) saved(t *testing.T) Summary {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var sum Summary
	if err := json.Unmarshal(s.data, &sum); err != nil {
		t.Fatalf("saved summary does not decode: %v (%q)", err, s.data)
	}
	return sum
}

type mail struct{ subject, body string }

type summaryCapture struct {
	mu       sync.Mutex
	emails   []mail
	webhooks []WebhookPayload
}

func (c *summaryCapture) email(subject, body string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.emails = append(c.emails, mail{subject, body})
	return nil
}

func (c *summaryCapture) webhook(p WebhookPayload) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.webhooks = append(c.webhooks, p)
	return nil
}

func (c *summaryCapture) sent() []mail {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]mail(nil), c.emails...)
}

var summaryNow = time.Date(2026, 6, 10, 9, 30, 0, 0, time.UTC)

func summaryCollector(opts Options) *Collector {
	if opts.Now == nil {
		opts.Now = func() time.Time { return summaryNow }
	}
	if opts.Location == nil {
		opts.Location = time.UTC
	}
	if opts.Host == "" {
		opts.Host = "host.example.com"
	}
	if opts.Interval == 0 {
		opts.Interval = time.Hour
	}
	if opts.SendOn == "" {
		opts.SendOn = "any"
	}
	return New(opts)
}

func summaryDueOf(c *Collector) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sum.Due
}

func summaryOf(c *Collector) Summary {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sum
}

// runStopped runs the collector with stop already closed: it loads, catches
// up a missed send, folds and saves, then returns.
func runStopped(t *testing.T, c *Collector) {
	t.Helper()
	stop := make(chan struct{})
	close(stop)
	done := make(chan struct{})
	go func() { defer close(done); c.Run(stop, nil) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after stop")
	}
}

func TestSummaryCounts(t *testing.T) {
	cap := &summaryCapture{}
	c := summaryCollector(Options{EmailSink: cap.email})
	c.NoteHandled([]Handled{
		{Check: "auto_block", Severity: "CRITICAL", IP: "203.0.113.5", BlockReason: "ModSecurity escalation: 5+ denies from 203.0.113.5 within 10m0s"},
		{Check: "auto_block", Severity: "CRITICAL", IP: "203.0.113.6", BlockReason: "Mail auth brute force from 203.0.113.6: 5 failed auths in 10m0s"},
		{Check: "auto_block", Severity: "CRITICAL", IP: "203.0.113.7", BlockReason: "rule escalation: 5+ denies"},
		{Check: "auto_block", Severity: "CRITICAL", IP: "203.0.113.7"},
		{Check: "auto_block", Severity: "WARNING", IP: "203.0.113.8"},
		{Check: "challenge_route", Severity: "WARNING", IP: "198.51.100.1"},
		{Check: "challenge_route", Severity: "HIGH", IP: "198.51.100.2"},
		{Check: "mail_bruteforce_suspected", Severity: "HIGH", IP: "198.51.100.3", Muted: true},
		{Check: "mail_bruteforce_suspected", Severity: "HIGH", IP: "198.51.100.4", Muted: true},
		{Check: "mail_bruteforce_suspected", Severity: "HIGH", IP: "198.51.100.5", Muted: true},
		{Check: "wp_login_bruteforce", Severity: "CRITICAL", IP: "192.0.2.10"},
	})

	s := summaryOf(c)
	if got := s.Checks["auto_block"]; got["CRITICAL"] != 4 || got["WARNING"] != 1 || len(got) != 2 {
		t.Fatalf("auto_block by severity = %v, want CRITICAL=4 WARNING=1", got)
	}
	if got := s.Checks["challenge_route"]; got["WARNING"] != 1 || got["HIGH"] != 1 {
		t.Fatalf("challenge_route by severity = %v", got)
	}
	if got := s.Checks["mail_bruteforce_suspected"]["HIGH"]; got != 3 {
		t.Fatalf("mail_bruteforce_suspected HIGH = %d, want 3", got)
	}
	if s.Blocks != 3 {
		t.Fatalf("Blocks = %d, want 3 (only findings with an applied block reason)", s.Blocks)
	}
	if s.BlockKinds["modsec"] != 2 || s.BlockKinds["mail-bruteforce"] != 1 || len(s.BlockKinds) != 2 {
		t.Fatalf("BlockKinds = %v, want modsec=2 mail-bruteforce=1", s.BlockKinds)
	}
	if s.Muted != 3 {
		t.Fatalf("Muted = %d, want 3", s.Muted)
	}

	if !c.SendDue(summaryDueOf(c)) {
		t.Fatal("due summary not sent")
	}
	sent := cap.sent()
	if len(sent) != 1 {
		t.Fatalf("emails = %d, want 1", len(sent))
	}
	body := sent[0].body
	for _, want := range []string{
		"Handled findings: 11",
		"Muted in alert email: 3",
		"Blocks applied: 3 (mail-bruteforce=1 modsec=2)",
		"Challenges: 2",
		"Mail login advisories, observe only: 3",
		"auto_block: CRITICAL=4 WARNING=1",
		"wp_login_bruteforce: CRITICAL=1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}
}

func TestSummaryTopSourcesBounded(t *testing.T) {
	cap := &summaryCapture{}
	c := summaryCollector(Options{
		EmailSink: cap.email,
		CountryOf: func(ip string) string {
			if ip == "203.0.113.9" {
				return "RO"
			}
			return ""
		},
	})
	for i := range 2000 {
		c.NoteHandled([]Handled{{Check: "challenge_route", Severity: "WARNING", IP: fmt.Sprintf("2001:db8::%x", i+1)}})
	}
	for range 50 {
		c.NoteHandled([]Handled{{Check: "wp_login_bruteforce", Severity: "CRITICAL", IP: "203.0.113.9"}})
	}
	if n := len(summaryOf(c).Sources); n > maxSummarySources {
		t.Fatalf("Sources = %d, want at most %d", n, maxSummarySources)
	}
	c.SendDue(summaryDueOf(c))
	sent := cap.sent()
	if len(sent) != 1 {
		t.Fatalf("emails = %d, want 1", len(sent))
	}
	body := sent[0].body
	_, top, ok := strings.Cut(body, "Top sources:\n")
	if !ok {
		t.Fatalf("body has no top sources:\n%s", body)
	}
	top, _, _ = strings.Cut(top, "\n\n")
	lines := strings.Split(strings.TrimRight(top, "\n"), "\n")
	if lines[0] != "  203.0.113.9 (RO): 52" {
		t.Fatalf("first top source = %q, want 203.0.113.9 with its country and count", lines[0])
	}
	listed := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "  ") {
			listed++
		}
	}
	if listed != summaryTopSources {
		t.Fatalf("top sources listed = %d, want %d:\n%s", listed, summaryTopSources, top)
	}
}

func TestNextSummaryDue(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		now      time.Time
		want     time.Time
		wantZone string
	}{
		{"before 08:00 on the spring-forward day", time.Date(2026, 3, 8, 7, 59, 0, 0, ny), time.Date(2026, 3, 8, 8, 0, 0, 0, ny), "EDT"},
		{"exactly 08:00 moves to the next day", time.Date(2026, 3, 8, 8, 0, 0, 0, ny), time.Date(2026, 3, 9, 8, 0, 0, 0, ny), "EDT"},
		{"before 08:00 on the fall-back day", time.Date(2026, 11, 1, 7, 30, 0, 0, ny), time.Date(2026, 11, 1, 8, 0, 0, 0, ny), "EST"},
		{"evening before spring-forward", time.Date(2026, 3, 7, 22, 0, 0, 0, ny), time.Date(2026, 3, 8, 8, 0, 0, 0, ny), "EDT"},
		{"evening before fall-back", time.Date(2026, 10, 31, 22, 0, 0, 0, ny), time.Date(2026, 11, 1, 8, 0, 0, 0, ny), "EST"},
		{"UTC input is read in the summary zone", time.Date(2026, 3, 8, 12, 30, 0, 0, time.UTC), time.Date(2026, 3, 9, 8, 0, 0, 0, ny), "EDT"},
	}
	for _, tc := range cases {
		got := nextSummaryDue(tc.now, ny)
		if !got.Equal(tc.want) {
			t.Errorf("%s: nextSummaryDue(%s) = %s, want %s", tc.name, tc.now, got, tc.want)
		}
		local := got.In(ny)
		if local.Hour() != summaryHour || local.Minute() != 0 {
			t.Errorf("%s: due %s is not 08:00 local", tc.name, local)
		}
		if zone, _ := local.Zone(); zone != tc.wantZone {
			t.Errorf("%s: due zone = %s, want %s", tc.name, zone, tc.wantZone)
		}
		if !got.After(tc.now) {
			t.Errorf("%s: due %s not after now %s", tc.name, got, tc.now)
		}
	}
}

func TestSummaryRestartKeepsCounts(t *testing.T) {
	st := &summaryStore{}
	first := summaryCollector(Options{LoadSummary: st.load, SaveSummary: st.save})
	first.NoteHandled([]Handled{
		{Check: "challenge_route", Severity: "WARNING", IP: "198.51.100.1"},
		{Check: "challenge_route", Severity: "WARNING", IP: "198.51.100.2"},
		{Check: "challenge_route", Severity: "WARNING", IP: "198.51.100.3"},
	})
	runStopped(t, first)
	if st.saves == 0 {
		t.Fatal("stop did not save the summary")
	}

	cap := &summaryCapture{}
	second := summaryCollector(Options{LoadSummary: st.load, SaveSummary: st.save, EmailSink: cap.email})
	runStopped(t, second)
	second.NoteHandled([]Handled{
		{Check: "challenge_route", Severity: "WARNING", IP: "198.51.100.4"},
		{Check: "challenge_route", Severity: "WARNING", IP: "198.51.100.5"},
	})
	if len(cap.sent()) != 0 {
		t.Fatalf("restart before the send time sent %d emails", len(cap.sent()))
	}
	if !second.SendDue(summaryDueOf(second)) {
		t.Fatal("due summary not sent")
	}
	sent := cap.sent()
	if len(sent) != 1 {
		t.Fatalf("emails = %d, want 1", len(sent))
	}
	if !strings.Contains(sent[0].body, "Challenges: 5") {
		t.Fatalf("summary after restart lost counts:\n%s", sent[0].body)
	}
	if !strings.Contains(sent[0].subject, "daily summary "+summaryNow.Format("2006-01-02")) {
		t.Fatalf("subject = %q, want the first collector's window start", sent[0].subject)
	}
}

// Counts noted before Run loads the saved window must survive the load.
func TestSummaryLoadKeepsCountsNotedBeforeRun(t *testing.T) {
	st := &summaryStore{}
	first := summaryCollector(Options{LoadSummary: st.load, SaveSummary: st.save})
	first.NoteHandled([]Handled{{Check: "challenge_route", Severity: "WARNING", IP: "198.51.100.1"}})
	runStopped(t, first)

	second := summaryCollector(Options{LoadSummary: st.load, SaveSummary: st.save})
	second.NoteHandled([]Handled{{Check: "challenge_route", Severity: "WARNING", IP: "198.51.100.1"}})
	runStopped(t, second)
	s := summaryOf(second)
	if got := s.Checks["challenge_route"]["WARNING"]; got != 2 {
		t.Fatalf("challenge_route = %d, want 2 (saved 1 + noted before load 1)", got)
	}
	if len(s.Sources) != 1 || s.Sources[0].IP != "198.51.100.1" || s.Sources[0].Count != 2 {
		t.Fatalf("Sources = %+v, want one merged source with count 2", s.Sources)
	}
}

func TestSummaryCatchUpSendsOnce(t *testing.T) {
	st := &summaryStore{}
	missed := newSummary(summaryNow.Add(-72*time.Hour), summaryNow.Add(-48*time.Hour))
	missed.note(Handled{Check: "challenge_route", Severity: "WARNING", IP: "198.51.100.1"})
	b, err := json.Marshal(missed)
	if err != nil {
		t.Fatal(err)
	}
	st.data = b

	cap := &summaryCapture{}
	c := summaryCollector(Options{LoadSummary: st.load, SaveSummary: st.save, EmailSink: cap.email})
	runStopped(t, c)
	sent := cap.sent()
	if len(sent) != 1 {
		t.Fatalf("catch-up emails = %d, want exactly 1", len(sent))
	}
	if !strings.Contains(sent[0].body, "Challenges: 1") {
		t.Fatalf("catch-up summary lost the missed window:\n%s", sent[0].body)
	}
	saved := st.saved(t)
	if want := nextSummaryDue(summaryNow, time.UTC); !saved.Due.Equal(want) {
		t.Fatalf("next Due = %s, want %s", saved.Due, want)
	}
	if !saved.Since.Equal(summaryNow) || len(saved.Checks) != 0 {
		t.Fatalf("rolled-over window = %+v, want empty since now", saved)
	}

	again := &summaryCapture{}
	restarted := summaryCollector(Options{LoadSummary: st.load, SaveSummary: st.save, EmailSink: again.email})
	runStopped(t, restarted)
	if n := len(again.sent()); n != 0 {
		t.Fatalf("second start sent %d emails, want 0", n)
	}
}

func TestSummarySavedAfterDelivery(t *testing.T) {
	var mu sync.Mutex
	var order []string
	record := func(s string) {
		mu.Lock()
		order = append(order, s)
		mu.Unlock()
	}
	st := &summaryStore{}
	c := summaryCollector(Options{
		EmailSink:   func(string, string) error { record("email"); return nil },
		WebhookSink: func(WebhookPayload) error { record("webhook"); return nil },
		SaveSummary: func(b []byte) error { record("save"); return st.save(b) },
	})
	c.NoteHandled([]Handled{{Check: "challenge_route", Severity: "WARNING", IP: "198.51.100.1"}})
	due := summaryDueOf(c)
	if !c.SendDue(due) {
		t.Fatal("due summary not sent")
	}
	mu.Lock()
	got := strings.Join(order, ",")
	mu.Unlock()
	if got != "save,email,save,webhook,save,save" {
		t.Fatalf("delivery order = %s, want a checkpoint before delivery, after each destination and after rollover", got)
	}
	saved := st.saved(t)
	if !saved.Since.Equal(due) || !saved.Due.Equal(nextSummaryDue(due, time.UTC)) || len(saved.Checks) != 0 {
		t.Fatalf("saved after delivery = %+v, want the empty next window", saved)
	}
	if c.SendDue(due) {
		t.Fatal("a second send at the same time went out")
	}
}

func TestSummaryDueClampedAfterClockStep(t *testing.T) {
	st := &summaryStore{}
	ahead := newSummary(summaryNow.Add(300*24*time.Hour), summaryNow.Add(301*24*time.Hour))
	ahead.note(Handled{Check: "challenge_route", Severity: "WARNING", IP: "198.51.100.1"})
	b, err := json.Marshal(ahead)
	if err != nil {
		t.Fatal(err)
	}
	st.data = b
	cap := &summaryCapture{}
	c := summaryCollector(Options{LoadSummary: st.load, SaveSummary: st.save, EmailSink: cap.email})
	runStopped(t, c)
	if n := len(cap.sent()); n != 0 {
		t.Fatalf("clamped window sent %d emails at start", n)
	}
	want := nextSummaryDue(summaryNow, time.UTC)
	if got := summaryDueOf(c); !got.Equal(want) {
		t.Fatalf("Due = %s, want clamped to %s", got, want)
	}
	if got := summaryOf(c); got.Checks["challenge_route"]["WARNING"] != 1 || !got.Since.Equal(summaryNow) {
		t.Fatalf("clamp dropped counts or kept a future start: %+v", got)
	}
	if !st.saved(t).Due.Equal(want) {
		t.Fatalf("saved Due = %s, want %s", st.saved(t).Due, want)
	}

	// A running collector whose clock goes back days is pulled in when the
	// send timer fires early.
	back := summaryNow.Add(-72 * time.Hour)
	if c.SendDue(back) {
		t.Fatal("sent before the send time")
	}
	if got, want := summaryDueOf(c), nextSummaryDue(back, time.UTC); !got.Equal(want) {
		t.Fatalf("Due after the clock went back = %s, want %s", got, want)
	}
}

func TestSummaryLoadFailureStartsFreshWindow(t *testing.T) {
	var errs []string
	c := summaryCollector(Options{
		LoadSummary: func() ([]byte, error) { return []byte("{not json"), nil },
		SaveSummary: func([]byte) error { return nil },
		OnError:     func(channel string, err error) { errs = append(errs, channel) },
	})
	c.NoteHandled([]Handled{{Check: "challenge_route", Severity: "WARNING", IP: "198.51.100.1"}})
	runStopped(t, c)
	if len(errs) != 1 || errs[0] != "summary" {
		t.Fatalf("OnError channels = %v, want [summary]", errs)
	}
	s := summaryOf(c)
	if !s.Due.Equal(nextSummaryDue(summaryNow, time.UTC)) || s.Checks["challenge_route"]["WARNING"] != 1 {
		t.Fatalf("window after a decode failure = %+v", s)
	}

	readErr := errors.New("fixture read failure")
	errs = nil
	c = summaryCollector(Options{
		LoadSummary: func() ([]byte, error) { return nil, readErr },
		OnError:     func(channel string, err error) { errs = append(errs, channel+":"+err.Error()) },
	})
	runStopped(t, c)
	if len(errs) != 1 || errs[0] != "summary:fixture read failure" {
		t.Fatalf("OnError = %v, want the read failure", errs)
	}
}

func TestTickFoldsWatchedBlocksIntoSummary(t *testing.T) {
	cap := &summaryCapture{}
	st := &summaryStore{}
	saved := make(chan struct{}, 1)
	c := summaryCollector(Options{
		Watch: true, MinBlock: 3, Countries: []string{"RO"},
		CountryOf:   func(string) string { return "RO" },
		EmailSink:   cap.email,
		WebhookSink: cap.webhook,
		SaveSummary: func(b []byte) error {
			if err := st.save(b); err != nil {
				return err
			}
			select {
			case saved <- struct{}{}:
			default:
			}
			return nil
		},
	})
	c.Observe("203.0.113.5", "ModSecurity escalation: 5+ denies", summaryNow)
	c.Observe("203.0.113.6", "Mail auth brute force from 203.0.113.6", summaryNow)

	stop := make(chan struct{})
	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() { defer close(done); c.Run(stop, tick) }()
	tick <- summaryNow
	select {
	case <-saved:
	case <-time.After(5 * time.Second):
		t.Fatal("tick did not save the summary")
	}
	close(stop)
	<-done

	if len(cap.sent()) != 0 || len(cap.webhooks) != 0 {
		t.Fatalf("tick called a sink: emails=%d webhooks=%d", len(cap.sent()), len(cap.webhooks))
	}
	w := st.saved(t).Watched
	if w.Total != 2 || w.ByCountry["RO"] != 2 || w.ByCategory["modsec"] != 1 || w.ByCategory["mail-bruteforce"] != 1 {
		t.Fatalf("saved watched counts = %+v, want RO=2", w)
	}
	if row := digestQueueStatuses(t, c, time.Now())["records"]; row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 0 {
		t.Fatalf("folded records still owned by the buffer: %+v", row)
	}

	c.SendDue(summaryDueOf(c))
	sent := cap.sent()
	if len(sent) != 1 {
		t.Fatalf("emails = %d, want 1", len(sent))
	}
	if strings.Contains(sent[0].body, "Watched-country blocks") {
		t.Fatalf("watched section shown below min_block:\n%s", sent[0].body)
	}

	shown := summaryCollector(Options{
		Watch: true, MinBlock: 2, Countries: []string{"RO"},
		CountryOf: func(string) string { return "RO" },
		EmailSink: cap.email,
	})
	shown.Observe("203.0.113.5", "ModSecurity escalation: 5+ denies", summaryNow)
	shown.Observe("203.0.113.6", "Mail auth brute force from 203.0.113.6", summaryNow)
	shown.SendDue(summaryDueOf(shown))
	sent = cap.sent()
	if len(sent) != 2 || !strings.Contains(sent[1].body, "Watched-country blocks: 2 (countries: RO)") || !strings.Contains(sent[1].body, "By country: RO=2") {
		t.Fatalf("watched section missing at min_block:\n%s", sent[len(sent)-1].body)
	}
}

func TestObserveIgnoredWithoutWatch(t *testing.T) {
	cap := &summaryCapture{}
	c := summaryCollector(Options{Live: true, MinBlock: 0, CountryOf: func(string) string { return "RO" }, WebhookSink: cap.webhook})
	c.Observe("203.0.113.5", "unrecognized customer block", summaryNow)
	if row := digestQueueStatuses(t, c, time.Now())["records"]; row.Depth != 0 {
		t.Fatalf("observation buffered without watch: %+v", row)
	}
	if len(cap.webhooks) != 0 {
		t.Fatalf("live alert sent without watch: %d", len(cap.webhooks))
	}
	if d := c.Drain(); d.Total != 0 {
		t.Fatalf("drain without watch = %+v", d)
	}
	c.SendDue(summaryDueOf(c))
	if len(cap.webhooks) != 1 {
		t.Fatalf("summary webhooks = %d, want 1", len(cap.webhooks))
	}
	if strings.Contains(cap.webhooks[0].Text, "Watched-country blocks") {
		t.Fatalf("watched section shown without watch:\n%s", cap.webhooks[0].Text)
	}
}

func TestSummaryEmailAndWebhook(t *testing.T) {
	cap := &summaryCapture{}
	c := summaryCollector(Options{
		Version:     "9.9.9",
		EmailSink:   cap.email,
		WebhookSink: cap.webhook,
		CountryOf: func(ip string) string {
			if ip == "203.0.113.5" {
				return "DE"
			}
			return ""
		},
	})
	c.NoteHandled([]Handled{
		{Check: "auto_block", Severity: "CRITICAL", IP: "203.0.113.5", BlockReason: "WordPress login brute force from 203.0.113.5"},
		{Check: "wp_login_bruteforce", Severity: "CRITICAL", IP: "203.0.113.5"},
	})
	due := summaryDueOf(c)
	if !c.SendDue(due) {
		t.Fatal("due summary not sent")
	}
	sent := cap.sent()
	if len(sent) != 1 || len(cap.webhooks) != 1 {
		t.Fatalf("emails=%d webhooks=%d, want 1/1", len(sent), len(cap.webhooks))
	}
	if want := "[CSM] host.example.com - daily summary " + summaryNow.Format("2006-01-02"); sent[0].subject != want {
		t.Fatalf("subject = %q, want %q", sent[0].subject, want)
	}
	for _, want := range []string{"Blocks applied: 1 (wp-bruteforce=1)", "203.0.113.5 (DE): 2"} {
		if !strings.Contains(sent[0].body, want) {
			t.Errorf("body missing %q:\n%s", want, sent[0].body)
		}
	}
	p := cap.webhooks[0]
	if p.CSM.Event != "daily_summary" || p.CSM.Host != "host.example.com" || p.CSM.Version != "9.9.9" {
		t.Fatalf("webhook meta = %+v", p.CSM)
	}
	if p.Text != sent[0].body {
		t.Fatalf("webhook text differs from the email body")
	}
	s := p.CSM.Summary
	if s == nil {
		t.Fatal("webhook carries no csm.summary")
	}
	if !s.Since.Equal(summaryNow) || !s.Due.Equal(due) || s.Blocks != 1 || s.BlockKinds["wp-bruteforce"] != 1 || s.Checks["wp_login_bruteforce"]["CRITICAL"] != 1 {
		t.Fatalf("csm.summary = %+v", s)
	}
	if len(s.Sources) != 1 || s.Sources[0] != (SourceCount{IP: "203.0.113.5", Count: 2, Country: "DE"}) {
		t.Fatalf("csm.summary sources = %+v", s.Sources)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"event":"daily_summary"`, `"summary":{`, `"block_kinds":{"wp-bruteforce":1}`} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("webhook JSON missing %s: %s", key, raw)
		}
	}
}
