package webui

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mailfwd/intel"
	"github.com/pidginhost/csm/internal/platform"
)

// eximWorld plays systemd-run and exim for the queue routes: the full -bp
// listing, -bp <id> with exim's missing-header reply for a message it does not
// hold, and the per-message actions applied to its queue. It records every
// exim argv with the systemd-run flags that wrapped it. Exim run directly
// fails, as it does inside csm's sandbox.
type eximWorld struct {
	mu           sync.Mutex
	queue        map[string]*worldMessage
	order        []string // listing order
	bpAnswer     map[string]string
	noSystemdRun bool
	listFails    bool
	listOutput   string // replaces the full listing when set
	actionErr    error  // returned by -Mrm and -Mg after they applied
	// probeFailsAfterAction makes systemd-run unable to start a unit once
	// an action ran, so only the read-back is refused.
	probeFailsAfterAction bool
	// release unblocks a delivery attempt a caller waits on.
	release chan struct{}
	calls   []eximCall
}

type worldMessage struct {
	frozen     bool
	sender     string
	recipients []string
}

type eximCall struct {
	flags, argv []string
}

func newEximWorld(t *testing.T) *eximWorld {
	w := &eximWorld{queue: map[string]*worldMessage{}, bpAnswer: map[string]string{}, release: make(chan struct{})}
	t.Cleanup(func() { close(w.release) })
	return w
}

func (w *eximWorld) add(id string, m worldMessage) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.queue[id] = &m
	w.order = append(w.order, id)
}

func (w *eximWorld) lookPath(file string) (string, error) {
	switch {
	case file == "systemd-run" && !w.noSystemdRun:
		return "/usr/bin/systemd-run", nil
	case file == "exim":
		return "/usr/sbin/exim", nil
	}
	return "", exec.ErrNotFound
}

// formatEntry prints m as exim -bp lists it under id.
func formatEntry(id string, m worldMessage) string {
	sender, state := "<"+m.sender+">", ""
	if m.frozen {
		state = " *** frozen ***"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "25m  1.0K %s %s%s\n", id, sender, state)
	for _, r := range m.recipients {
		fmt.Fprintf(&b, "          %s\n", r)
	}
	b.WriteString("\n")
	return b.String()
}

func (w *eximWorld) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	var flags, argv []string
	if name == "/usr/bin/systemd-run" {
		sep := slices.Index(args, "--")
		flags, argv = args[:sep], args[sep+1:]
	} else {
		argv = append([]string{name}, args...)
	}
	w.mu.Lock()
	if argv[0] == "/bin/true" {
		defer w.mu.Unlock()
		if w.probeFailsAfterAction && slices.ContainsFunc(w.calls, func(c eximCall) bool { return strings.HasPrefix(c.argv[1], "-M") }) {
			return nil, errors.New("Failed to connect to bus: No such file or directory")
		}
		return nil, nil
	}
	w.calls = append(w.calls, eximCall{flags: flags, argv: argv})
	if flags == nil {
		w.mu.Unlock()
		return nil, errors.New("exim: cannot open main log: Read-only file system")
	}
	if argv[1] == "-M" && (slices.Contains(flags, "--wait") || slices.Contains(flags, "--pipe")) {
		// A delivery attempt to an unresponsive server: whoever waits for
		// the unit waits until the attempt gives up.
		w.mu.Unlock()
		select {
		case <-w.release:
		case <-ctx.Done():
		}
		return nil, errors.New("delivery attempt still running")
	}
	defer w.mu.Unlock()
	switch {
	case argv[1] == "-bpc":
		return []byte(fmt.Sprintf("%d\n", len(w.queue))), nil
	case argv[1] == "-bp" && len(argv) == 2:
		if w.listFails {
			return nil, errors.New("exit status 1")
		}
		if w.listOutput != "" {
			return []byte(w.listOutput), nil
		}
		var b strings.Builder
		for _, id := range w.order {
			if m, ok := w.queue[id]; ok {
				b.WriteString(formatEntry(id, *m))
			}
		}
		return []byte(b.String()), nil
	case argv[1] == "-bp":
		if out, ok := w.bpAnswer[argv[2]]; ok {
			return []byte(out), nil
		}
		if _, ok := w.queue[argv[2]]; !ok {
			return []byte(fmt.Sprintf("   0 %s\n    *** spool read error: No such file or directory ***\n\n", argv[2])), nil
		}
		return []byte(formatEntry(argv[2], *w.queue[argv[2]])), nil
	case argv[1] == "-Mrm", argv[1] == "-Mg":
		delete(w.queue, argv[2])
		return nil, w.actionErr
	case argv[1] == "-Mt":
		if m, ok := w.queue[argv[2]]; ok {
			m.frozen = false
		}
	}
	return nil, nil
}

// runs returns the recorded exim argv lists whose option is flag.
func (w *eximWorld) runs(flag string) []eximCall {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []eximCall
	for _, c := range w.calls {
		if len(c.argv) > 1 && c.argv[1] == flag && (flag != "-bp" || len(c.argv) == 2) {
			out = append(out, c)
		}
	}
	return out
}

func (w *eximWorld) callCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.calls)
}

// countingAdmin counts the msglog reads the real admin makes.
type countingAdmin struct {
	intel.QueueAdmin
	mu      sync.Mutex
	reasons []string
}

func (c *countingAdmin) Reason(id string) (intel.StuckReason, []string, error) {
	c.mu.Lock()
	c.reasons = append(c.reasons, id)
	c.mu.Unlock()
	return c.QueueAdmin.Reason(id)
}

// queueServer wires a test server to world for both the cached listing and
// the per-message admin, with msglogs under spool.
func queueServer(t *testing.T, world *eximWorld) (*Server, *countingAdmin, string) {
	t.Helper()
	withEximProbe(t, world.lookPath, world.run)
	s := newTestServer(t, "tok")
	spool := t.TempDir()
	admin := &countingAdmin{QueueAdmin: intel.NewEximQueueAdmin(spool, world.lookPath, world.run)}
	s.queueAdmin = admin
	return s, admin, spool
}

func writeQueueMsglog(t *testing.T, spool, id, content string) {
	t.Helper()
	dir := filepath.Join(spool, "msglog", id[5:6])
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func queueRequest(t *testing.T, s *Server, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	return w
}

type queueListBody struct {
	Items []struct {
		intel.QueueMessage
		Reason intel.StuckReason `json:"reason"`
	} `json:"items"`
	Total         *int       `json:"total"`
	Queued        *int       `json:"queued"`
	Page          int        `json:"page"`
	Limit         int        `json:"limit"`
	Frozen        *int       `json:"frozen"`
	Backscatter   *int       `json:"backscatter"`
	OldestSeconds *int       `json:"oldest_seconds"`
	Unavailable   bool       `json:"unavailable"`
	ListedAt      *time.Time `json:"listed_at"`
}

func getQueueList(t *testing.T, s *Server, query string) queueListBody {
	t.Helper()
	w := queueRequest(t, s, http.MethodGet, "/api/v1/email/queue"+query)
	if w.Code != http.StatusOK {
		t.Fatalf("GET queue%s: status %d: %s", query, w.Code, w.Body.String())
	}
	var body queueListBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return body
}

func (b queueListBody) ids() []string {
	ids := make([]string, len(b.Items))
	for i, it := range b.Items {
		ids[i] = it.ID
	}
	return ids
}

func lastAudit(t *testing.T, s *Server) UIAuditEntry {
	t.Helper()
	f, err := os.Open(filepath.Join(s.cfg.StatePath, uiAuditFile))
	if err != nil {
		t.Fatalf("audit log: %v", err)
	}
	defer f.Close()
	var entry UIAuditEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if err := json.Unmarshal(sc.Bytes(), &entry); err != nil {
			t.Fatalf("audit line: %v", err)
		}
	}
	return entry
}

// Message IDs whose first six characters order their arrival.
const (
	qOldest = "1tAAAA-000001-Ab"
	qOld    = "1tBBBB-000002-Ab"
	qMid    = "1tCCCC-000003-Ab"
	qNew    = "1tDDDD-000004-Ab"
	qNewest = "1tEEEE-000005-Ab"
)

func TestQueueListPagingAndFilters(t *testing.T) {
	world := newEximWorld(t)
	// Listed newest first so the route has to order them.
	world.add(qNewest, worldMessage{sender: "news@example.com", recipients: []string{"Reader@Example.NET"}})
	world.add(qNew, worldMessage{frozen: true, recipients: []string{"gone@example.net"}})
	world.add(qMid, worldMessage{sender: "billing@example.com", recipients: []string{"a@example.net", "b@example.net"}})
	world.add(qOld, worldMessage{recipients: []string{"unknown@example.net"}})
	world.add(qOldest, worldMessage{frozen: true, sender: "sender@example.com", recipients: []string{"rcpt@example.net"}})
	s, _, spool := queueServer(t, world)
	frozenLog := "2026-10-21 06:10:01 rcpt@example.net R=lookuphost T=remote_smtp defer (-53): retry time not reached\n*** Frozen (delivery error message)\n"
	writeQueueMsglog(t, spool, qOldest, frozenLog)
	writeQueueMsglog(t, spool, qMid, frozenLog) // thawed since it froze

	all := getQueueList(t, s, "")
	if got, want := all.ids(), []string{qOldest, qOld, qMid, qNew, qNewest}; !slices.Equal(got, want) {
		t.Fatalf("ids = %v, want oldest first %v", got, want)
	}
	if all.Total == nil || *all.Total != 5 || all.Queued == nil || *all.Queued != 5 || all.Page != 1 || all.Limit != 25 || all.Unavailable {
		t.Errorf("paging = total %v queued %v page %d limit %d unavailable %v, want 5, 5, 1, 25, false", all.Total, all.Queued, all.Page, all.Limit, all.Unavailable)
	}
	if all.Frozen == nil || *all.Frozen != 2 || all.Backscatter == nil || *all.Backscatter != 2 || all.OldestSeconds == nil || *all.OldestSeconds != 25*60 {
		t.Errorf("summary = frozen %v backscatter %v oldest %v, want 2, 2, 1500", all.Frozen, all.Backscatter, all.OldestSeconds)
	}
	reasons := map[string]string{}
	for _, it := range all.Items {
		reasons[it.ID] = it.Reason.Class
	}
	if reasons[qOldest] != "frozen" || reasons[qMid] != "retry_wait" || reasons[qNew] != "none" {
		t.Errorf("reasons = %v, want frozen, thawed shown as retry_wait, none without a msglog", reasons)
	}

	page2 := getQueueList(t, s, "?page=2&limit=2")
	if got := page2.ids(); !slices.Equal(got, []string{qMid, qNew}) || *page2.Total != 5 || page2.Page != 2 || page2.Limit != 2 {
		t.Errorf("page 2 of 2 = %v total %d page %d limit %d, want [%s %s] of 5", got, *page2.Total, page2.Page, page2.Limit, qMid, qNew)
	}
	if beyond := getQueueList(t, s, "?page=9223372036854775807&limit=100"); len(beyond.Items) != 0 || *beyond.Total != 5 {
		t.Errorf("page past the end = %v total %d, want no items of 5", beyond.ids(), *beyond.Total)
	}
	for query, wantLimit := range map[string]int{"?limit=500": 100, "?limit=0": 25, "?limit=-3": 25, "?limit=x": 25} {
		if got := getQueueList(t, s, query); got.Limit != wantLimit || got.Page != 1 {
			t.Errorf("%s: limit %d page %d, want %d and page 1", query, got.Limit, got.Page, wantLimit)
		}
	}
	if got := getQueueList(t, s, "?page=0"); got.Page != 1 || len(got.Items) != 5 {
		t.Errorf("page=0: page %d with %d items, want page 1 with all 5", got.Page, len(got.Items))
	}

	for query, want := range map[string][]string{
		"?filter=all":                     {qOldest, qOld, qMid, qNew, qNewest},
		"?filter=frozen":                  {qOldest, qNew},
		"?filter=backscatter":             {qOld, qNew},
		"?q=example.net":                  {qOldest, qOld, qMid, qNew, qNewest},
		"?q=unknown":                      {qOld},
		"?q=READER%40example.net":         {qNewest},
		"?q=billing":                      {qMid},
		"?filter=frozen&q=gone":           {qNew},
		"?filter=backscatter&q=nothing-x": {},
	} {
		got := getQueueList(t, s, query)
		if !slices.Equal(got.ids(), want) || *got.Total != len(want) {
			t.Errorf("%s = %v (total %d), want %v", query, got.ids(), *got.Total, want)
		}
		// The summary describes the whole queue whatever the filter.
		if got.Queued == nil || *got.Queued != 5 || *got.Frozen != 2 || *got.Backscatter != 2 {
			t.Errorf("%s: queued %v frozen %d backscatter %d, want the whole queue's 5, 2 and 2", query, got.Queued, *got.Frozen, *got.Backscatter)
		}
	}

	if w := queueRequest(t, s, http.MethodGet, "/api/v1/email/queue?filter=deferred"); w.Code != http.StatusBadRequest {
		t.Errorf("unknown filter: status %d, want 400", w.Code)
	}
	if n := len(world.runs("-bp")); n != 1 {
		t.Errorf("full listings = %d, want one cached listing for every request", n)
	}
}

// The list comes from a listing up to a minute old, so it says when that
// listing ran: its counts can trail the live size the card shows.
func TestQueueListSaysWhenItListed(t *testing.T) {
	world := newEximWorld(t)
	world.add(qMid, worldMessage{sender: "sender@example.com", recipients: []string{"rcpt@example.net"}})
	s, _, _ := queueServer(t, world)
	before := time.Now()
	first := getQueueList(t, s, "")
	after := time.Now()
	if first.ListedAt == nil || first.ListedAt.Before(before.Truncate(time.Second)) || first.ListedAt.After(after) {
		t.Fatalf("listed_at = %v, want the listing time between %v and %v", first.ListedAt, before, after)
	}
	if again := getQueueList(t, s, ""); again.ListedAt == nil || !again.ListedAt.Equal(*first.ListedAt) {
		t.Errorf("cached list listed_at = %v, want the listing's %v", again.ListedAt, first.ListedAt)
	}
}

// The listing keeps the first 50 undelivered recipients of each message, so
// q matches the sender and those recipients only, as api.md says.
func TestQueueSearchMatchesTheFirstFiftyRecipients(t *testing.T) {
	world := newEximWorld(t)
	var rcpts []string
	for i := 0; i < 60; i++ {
		rcpts = append(rcpts, fmt.Sprintf("r%02d@example.net", i))
	}
	world.add(qMid, worldMessage{sender: "sender@example.com", recipients: rcpts})
	s, _, _ := queueServer(t, world)
	for q, want := range map[string]int{"sender%40example.com": 1, "r49%40": 1, "r50%40": 0} {
		if got := getQueueList(t, s, "?q="+q); *got.Total != want {
			t.Errorf("q=%s: total %d, want %d", q, *got.Total, want)
		}
	}
}

func TestQueueListReadsOnlyPageMsglogs(t *testing.T) {
	world := newEximWorld(t)
	for i := 0; i < 2000; i++ {
		world.add(fmt.Sprintf("1tAbCd-%06d-Ab", i), worldMessage{sender: "sender@example.com", recipients: []string{"rcpt@example.net"}})
	}
	s, admin, _ := queueServer(t, world)

	first := getQueueList(t, s, "?page=1&limit=25")
	if len(first.Items) != 25 || *first.Total != 2000 {
		t.Fatalf("page 1 = %d items of %d, want 25 of 2000", len(first.Items), *first.Total)
	}
	if !slices.Equal(admin.reasons, first.ids()) {
		t.Fatalf("msglog reads = %d (%v), want exactly the 25 listed messages", len(admin.reasons), admin.reasons)
	}
	getQueueList(t, s, "?page=1&limit=25")
	if len(admin.reasons) != 25 {
		t.Errorf("msglog reads after a repeat = %d, want the 25 cached reasons reused", len(admin.reasons))
	}
	getQueueList(t, s, "?page=2&limit=25")
	if len(admin.reasons) != 50 {
		t.Errorf("msglog reads after page 2 = %d, want 50", len(admin.reasons))
	}
	if n := len(world.runs("-bp")); n != 1 {
		t.Errorf("full listings = %d, want one", n)
	}
}

// Reasons are cached for a minute per message, and nothing older survives a
// later page, so the cache holds at most the messages listed in the last
// minute.
func TestQueueReasonCacheBounded(t *testing.T) {
	world := newEximWorld(t)
	s, admin, _ := queueServer(t, world)
	msgs := []intel.QueueMessage{{ID: qOldest}, {ID: qOld}, {ID: qMid}, {ID: qNew}}
	t0 := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

	s.pageReasons(t0, msgs[:3])
	s.pageReasons(t0.Add(59*time.Second), msgs[:3])
	if len(admin.reasons) != 3 {
		t.Fatalf("reads within the minute = %d, want 3", len(admin.reasons))
	}
	s.pageReasons(t0.Add(time.Minute), msgs[3:])
	s.queueReasonMu.Lock()
	cached := len(s.queueReasons)
	s.queueReasonMu.Unlock()
	if cached != 1 || len(admin.reasons) != 4 {
		t.Errorf("after a minute: %d cached, %d reads, want only the new page's reason cached after 4 reads", cached, len(admin.reasons))
	}
	s.pageReasons(t0.Add(time.Minute), msgs[:1])
	if len(admin.reasons) != 5 {
		t.Errorf("reads = %d, want an expired reason read again", len(admin.reasons))
	}
}

func TestQueueListUnavailable(t *testing.T) {
	for name, setup := range map[string]func(*eximWorld){
		"exim fails":      func(w *eximWorld) { w.listFails = true },
		"listing garbled": func(w *eximWorld) { w.listOutput = "exim: unexpected reply\n" },
		"partial listing": func(w *eximWorld) {
			w.listOutput = formatEntry(qMid, worldMessage{sender: "sender@example.com"}) +
				"   0 " + qNew + "\n    *** spool read error: Permission denied ***\n"
		},
	} {
		t.Run(name, func(t *testing.T) {
			world := newEximWorld(t)
			setup(world)
			s, admin, _ := queueServer(t, world)
			assertQueueUnknown(t, s, admin)
		})
	}

	// An overview poll saw the queue empty. Mail arrived since and the
	// listing fails: the old empty count must not stand in for it.
	t.Run("refilled after an empty count", func(t *testing.T) {
		world := newEximWorld(t)
		s, admin, _ := queueServer(t, world)
		if q := queueSnapshot(time.Now()); q.Size != 0 || q.Unavailable {
			t.Fatalf("snapshot = %+v, want an empty queue", q)
		}
		world.add(qMid, worldMessage{recipients: []string{"rcpt@example.net"}})
		world.listFails = true
		assertQueueUnknown(t, s, admin)
	})
}

// assertQueueUnknown checks that the list says the queue is unknown and
// carries nothing that could read as its size.
func assertQueueUnknown(t *testing.T, s *Server, admin *countingAdmin) {
	t.Helper()
	w := queueRequest(t, s, http.MethodGet, "/api/v1/email/queue")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if string(raw["unavailable"]) != "true" || string(raw["items"]) != "[]" {
		t.Errorf("body = %s, want unavailable with no items", w.Body.String())
	}
	for _, key := range []string{"total", "queued", "frozen", "backscatter", "oldest_seconds", "listed_at"} {
		if _, ok := raw[key]; ok {
			t.Errorf("unavailable queue carries %q: %s", key, w.Body.String())
		}
	}
	if len(admin.reasons) != 0 {
		t.Errorf("msglogs read for an unknown queue: %v", admin.reasons)
	}
}

func TestQueueDetail(t *testing.T) {
	world := newEximWorld(t)
	var rcpts []string
	for i := 0; i < 60; i++ {
		rcpts = append(rcpts, fmt.Sprintf("r%02d@example.net", i))
	}
	world.add(qMid, worldMessage{sender: "sender@example.com", recipients: rcpts})
	world.add(qNew, worldMessage{frozen: true, recipients: []string{"gone@example.net"}})
	s, _, spool := queueServer(t, world)
	var log strings.Builder
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&log, "2026-10-21 10:%02d:00 H=mx6.example.net [203.0.113.25] SMTP error from remote mail server after RCPT TO:<r00@example.net>: 451 4.7.1 Greylisted, please try again later\n", i)
	}
	writeQueueMsglog(t, spool, qMid, log.String())

	w := queueRequest(t, s, http.MethodGet, "/api/v1/email/queue/"+qMid)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var got struct {
		intel.QueueMessage
		Reason intel.StuckReason `json:"reason"`
		Msglog []string          `json:"msglog"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != qMid || got.Sender != "sender@example.com" || !slices.Equal(got.Recipients, rcpts) || got.RecipientCount != 60 {
		t.Errorf("message = %s %s %d recipients (count %d), want all 60 recipients", got.ID, got.Sender, len(got.Recipients), got.RecipientCount)
	}
	if got.Reason.Class != "greylisted" || len(got.Msglog) != 20 || !strings.HasPrefix(got.Msglog[19], "2026-10-21 10:29:00") {
		t.Errorf("reason %+v with %d msglog lines, want greylisted with the last 20 lines", got.Reason, len(got.Msglog))
	}

	w = queueRequest(t, s, http.MethodGet, "/api/v1/email/queue/"+qNew)
	if !strings.Contains(w.Body.String(), `"msglog":[]`) || !strings.Contains(w.Body.String(), `"class":"none"`) {
		t.Errorf("message without a msglog: %s, want no lines and no attempt", w.Body.String())
	}

	world.bpAnswer[qOld] = formatEntry(qMid, worldMessage{recipients: rcpts}) // exim answers with another message
	for _, id := range []string{qNewest, qOld} {
		if w := queueRequest(t, s, http.MethodGet, "/api/v1/email/queue/"+id); w.Code != http.StatusNotFound {
			t.Errorf("GET %s: status %d, want 404", id, w.Code)
		}
	}
	if w := queueRequest(t, s, http.MethodPost, "/api/v1/email/queue/"+qMid); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST detail: status %d, want 405", w.Code)
	}

	// The read runs exim, which aborts inside csm's sandbox; without
	// systemd-run it is not attempted.
	world.noSystemdRun = true
	before := world.callCount()
	if w := queueRequest(t, s, http.MethodGet, "/api/v1/email/queue/"+qMid); w.Code != http.StatusServiceUnavailable {
		t.Errorf("GET without systemd-run: status %d %s, want 503", w.Code, w.Body.String())
	}
	if n := world.callCount(); n != before {
		t.Errorf("without systemd-run exim ran directly: %v", world.calls[before:])
	}
}

func TestQueueActionRejectsNonIDs(t *testing.T) {
	world := newEximWorld(t)
	world.add(qMid, worldMessage{frozen: true, recipients: []string{"rcpt@example.net"}})
	s, _, _ := queueServer(t, world)

	for _, path := range []string{
		"/api/v1/email/queue/-qff/retry",
		"/api/v1/email/queue/-Mrm/delete",
		"/api/v1/email/queue/..%2Fx/delete",
		"/api/v1/email/queue/1tAbCd-000001-Ab;rm/delete",
		"/api/v1/email/queue/1tAbCd-000001-Ab%20/delete",
		"/api/v1/email/queue/1tAbCd-000001-Ab%0A/thaw",
		"/api/v1/email/queue/" + qMid + "/freeze",
		"/api/v1/email/queue/" + qMid + "/-Mrm",
	} {
		if w := queueRequest(t, s, http.MethodPost, path); w.Code != http.StatusBadRequest {
			t.Errorf("POST %s: status %d, want 400: %s", path, w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/api/v1/email/queue/-qff", "/api/v1/email/queue/..%2Fx", "/api/v1/email/queue/1tAbCd-000001-Ab%20"} {
		if w := queueRequest(t, s, http.MethodGet, path); w.Code != http.StatusBadRequest {
			t.Errorf("GET %s: status %d, want 400", path, w.Code)
		}
	}
	if n := world.callCount(); n != 0 {
		t.Fatalf("exim ran %d time(s) for rejected IDs: %v", n, world.calls)
	}
}

func TestQueueActionMessageGone(t *testing.T) {
	world := newEximWorld(t)
	s, _, _ := queueServer(t, world)
	// exim answers with another message.
	world.bpAnswer[qOld] = formatEntry(qMid, worldMessage{recipients: []string{"rcpt@example.net"}})

	for _, id := range []string{qMid, qOld} {
		w := queueRequest(t, s, http.MethodPost, "/api/v1/email/queue/"+id+"/delete")
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"outcome":"gone"`) {
			t.Errorf("%s: status %d body %s, want 409 with outcome gone", id, w.Code, w.Body.String())
		}
		if a := lastAudit(t, s); a.Action != "email_queue_delete" || a.Target != id || !strings.Contains(a.Details, "gone") {
			t.Errorf("%s: audit = %+v, want email_queue_delete for the ID with outcome gone", id, a)
		}
	}
	if runs := world.runs("-Mrm"); len(runs) != 0 {
		t.Fatalf("delete ran on a message that is gone: %v", runs)
	}
}

func TestQueueActionsRunRequiredUnits(t *testing.T) {
	for _, tc := range []struct {
		action, flag, outcome string
	}{
		{"retry", "-M", "attempt_started"},
		{"bounce", "-Mg", "bounced"},
		{"delete", "-Mrm", "removed"},
		{"thaw", "-Mt", "thawed"},
	} {
		t.Run(tc.action, func(t *testing.T) {
			world := newEximWorld(t)
			world.add(qMid, worldMessage{frozen: true, sender: "sender@example.com", recipients: []string{"rcpt@example.net"}})
			s, _, _ := queueServer(t, world)

			w := queueRequest(t, s, http.MethodPost, "/api/v1/email/queue/"+qMid+"/"+tc.action)
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"outcome":"`+tc.outcome+`"`) {
				t.Fatalf("status %d body %s, want 200 with outcome %s", w.Code, w.Body.String(), tc.outcome)
			}
			runs := world.runs(tc.flag)
			if len(runs) != 1 {
				t.Fatalf("%s runs = %v, want one", tc.flag, runs)
			}
			if !slices.Equal(runs[0].argv, []string{"/usr/sbin/exim", tc.flag, qMid}) {
				t.Errorf("argv = %v, want exactly exim %s %s", runs[0].argv, tc.flag, qMid)
			}
			waits := slices.Contains(runs[0].flags, "--wait") || slices.Contains(runs[0].flags, "--pipe")
			if tc.action == "retry" && waits {
				t.Errorf("retry flags = %v, want neither --wait nor --pipe", runs[0].flags)
			}
			if tc.action != "retry" && !waits {
				t.Errorf("%s flags = %v, want the unit waited on before verifying", tc.action, runs[0].flags)
			}
			if a := lastAudit(t, s); a.Action != "email_queue_"+tc.action || a.Target != qMid || !strings.Contains(a.Details, tc.outcome) {
				t.Errorf("audit = %+v, want email_queue_%s for the ID with outcome %s", a, tc.action, tc.outcome)
			}

			// Required: without systemd-run the action never runs inside the
			// sandbox.
			world = newEximWorld(t)
			world.add(qMid, worldMessage{frozen: true, recipients: []string{"rcpt@example.net"}})
			world.noSystemdRun = true
			s, _, _ = queueServer(t, world)
			w = queueRequest(t, s, http.MethodPost, "/api/v1/email/queue/"+qMid+"/"+tc.action)
			if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), `"outcome":"unchanged"`) {
				t.Errorf("without systemd-run: status %d body %s, want 503 unchanged", w.Code, w.Body.String())
			}
			if runs := world.runs(tc.flag); len(runs) != 0 {
				t.Errorf("without systemd-run exim ran directly: %v", runs)
			}
		})
	}
}

func TestQueueRetryDoesNotWait(t *testing.T) {
	world := newEximWorld(t)
	world.add(qMid, worldMessage{frozen: true, recipients: []string{"rcpt@example.net"}})
	s, _, _ := queueServer(t, world)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/queue/"+qMid+"/retry", nil)
	req.Header.Set("Authorization", "Bearer tok")
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		s.httpSrv.Handler.ServeHTTP(w, req)
		done <- w
	}()
	select {
	case w := <-done:
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"outcome":"attempt_started"`) {
			t.Fatalf("status %d body %s, want 200 attempt_started", w.Code, w.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retry did not return within 2 s while the delivery attempt runs")
	}
}

// A thaw on a message that is no longer frozen (a stale list, auto_thaw or
// another admin) is not a failure, and exim has nothing to do.
func TestQueueThawNotFrozen(t *testing.T) {
	world := newEximWorld(t)
	world.add(qMid, worldMessage{recipients: []string{"rcpt@example.net"}})
	s, _, _ := queueServer(t, world)

	w := queueRequest(t, s, http.MethodPost, "/api/v1/email/queue/"+qMid+"/thaw")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"outcome":"unchanged"`) {
		t.Fatalf("status %d body %s, want 200 unchanged", w.Code, w.Body.String())
	}
	if runs := world.runs("-Mt"); len(runs) != 0 {
		t.Errorf("thaw ran on a message that is not frozen: %v", runs)
	}
	if a := lastAudit(t, s); a.Action != "email_queue_thaw" || a.Target != qMid || a.Details != "outcome: unchanged" {
		t.Errorf("audit = %+v, want email_queue_thaw with outcome unchanged", a)
	}
}

// exim can fail an action, "locked" say, while a delivery takes the
// message. It left the queue, but the action cannot claim it: the outcome is
// gone, and the audit entry still records what exim said.
func TestQueueActionAuditsRunError(t *testing.T) {
	world := newEximWorld(t)
	world.add(qMid, worldMessage{recipients: []string{"rcpt@example.net"}})
	world.actionErr = errors.New("exit status 1")
	s, _, _ := queueServer(t, world)

	w := queueRequest(t, s, http.MethodPost, "/api/v1/email/queue/"+qMid+"/delete")
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"outcome":"gone"`) {
		t.Fatalf("status %d body %s, want 409 gone", w.Code, w.Body.String())
	}
	if a := lastAudit(t, s); a.Action != "email_queue_delete" || !strings.HasPrefix(a.Details, "outcome: gone; ") || !strings.Contains(a.Details, "exit status 1") {
		t.Errorf("audit = %+v, want outcome gone with exim's exit status", a)
	}
}

// The action ran, so a refused read-back is an unknown outcome (500), not the
// 503 that says nothing ran.
func TestQueueActionReadBackRefused(t *testing.T) {
	world := newEximWorld(t)
	world.add(qMid, worldMessage{recipients: []string{"rcpt@example.net"}})
	world.probeFailsAfterAction = true
	s, _, _ := queueServer(t, world)

	w := queueRequest(t, s, http.MethodPost, "/api/v1/email/queue/"+qMid+"/delete")
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), `"outcome":"unchanged"`) || strings.Contains(w.Body.String(), "need systemd-run") {
		t.Fatalf("status %d body %s, want 500 unchanged, not the systemd-run refusal", w.Code, w.Body.String())
	}
	if runs := world.runs("-Mrm"); len(runs) != 1 {
		t.Fatalf("-Mrm runs = %v, want the one that ran", runs)
	}
	if a := lastAudit(t, s); a.Action != "email_queue_delete" || !strings.Contains(a.Details, "could not be read back") {
		t.Errorf("audit = %+v, want the delete with its unreadable outcome", a)
	}
}

// A successful action must show in the next list rather than wait out the
// cached listing.
func TestQueueActionRefreshesList(t *testing.T) {
	world := newEximWorld(t)
	world.add(qOld, worldMessage{recipients: []string{"rcpt@example.net"}})
	world.add(qMid, worldMessage{recipients: []string{"rcpt@example.net"}})
	s, _, _ := queueServer(t, world)
	getQueueList(t, s, "")

	if w := queueRequest(t, s, http.MethodPost, "/api/v1/email/queue/"+qMid+"/delete"); w.Code != http.StatusOK {
		t.Fatalf("delete: status %d %s", w.Code, w.Body.String())
	}
	if got := getQueueList(t, s, "").ids(); !slices.Equal(got, []string{qOld}) {
		t.Errorf("list after delete = %v, want only %s", got, qOld)
	}
}

func TestQueueActionsAdminAndCSRF(t *testing.T) {
	world := newEximWorld(t)
	world.add(qMid, worldMessage{frozen: true, recipients: []string{"rcpt@example.net"}})
	s, _, _ := queueServer(t, world)
	s.cfg.WebUI.Tokens = append(s.cfg.WebUI.Tokens, config.WebUIToken{Name: "reader", Token: "read-tok", Scope: "read", IssuedAt: time.Now().UTC().Format(time.RFC3339)})

	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/email/queue"},
		{http.MethodGet, "/api/v1/email/queue/" + qMid},
		{http.MethodPost, "/api/v1/email/queue/" + qMid + "/delete"},
	} {
		req := httptest.NewRequest(rt.method, rt.path, nil)
		req.Header.Set("Authorization", "Bearer read-tok")
		w := httptest.NewRecorder()
		s.httpSrv.Handler.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("read token %s %s: status %d, want 401", rt.method, rt.path, w.Code)
		}
	}

	cookie := testBrowserCookie(t, s, "tok")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/queue/"+qMid+"/delete", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("browser POST without CSRF: status %d, want 403", w.Code)
	}
	if n := world.callCount(); n != 0 {
		t.Fatalf("exim ran %d time(s) for refused requests", n)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/email/queue/"+qMid+"/thaw", nil)
	req.AddCookie(cookie)
	setSessionCSRF(s, req)
	w = httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("browser POST with CSRF: status %d %s, want 200", w.Code, w.Body.String())
	}
	if a := lastAudit(t, s); a.Via != "browser" || a.Action != "email_queue_thaw" {
		t.Errorf("audit = %+v, want the browser's thaw", a)
	}
}

func TestQueueRoutesUnavailableOffCPanel(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	panel := platform.PanelNone
	if !platform.SetOverrides(platform.Overrides{Panel: &panel}) {
		t.Fatal("platform override rejected before Detect")
	}
	if got := selectQueueAdmin(); got != nil {
		t.Fatalf("selectQueueAdmin returned %T, want nil off cPanel", got)
	}

	s := newTestServer(t, "tok")
	s.queueAdmin = nil
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/email/queue"},
		{http.MethodGet, "/api/v1/email/queue/" + qMid},
		{http.MethodPost, "/api/v1/email/queue/" + qMid + "/delete"},
	} {
		if w := queueRequest(t, s, rt.method, rt.path); w.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s: status %d, want 503", rt.method, rt.path, w.Code)
		}
	}
}

func TestSelectQueueAdminUsesEximOnCPanel(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	panel := platform.PanelCPanel
	if !platform.SetOverrides(platform.Overrides{Panel: &panel}) {
		t.Fatal("platform override rejected before Detect")
	}
	if _, ok := selectQueueAdmin().(*intel.EximQueueAdmin); !ok {
		t.Fatalf("selectQueueAdmin returned %T, want *intel.EximQueueAdmin", selectQueueAdmin())
	}
}

func TestQueueListFailedRefreshAfterEmptyListing(t *testing.T) {
	world := newEximWorld(t)
	s, admin, _ := queueServer(t, world)
	if got := getQueueList(t, s, ""); got.Unavailable || got.Queued == nil || *got.Queued != 0 {
		t.Fatalf("initial list = %+v, want a known empty queue", got)
	}
	queueDetail.Lock()
	queueDetail.state.tried = time.Now().Add(-2 * queueDetailTTL)
	queueDetail.Unlock()
	world.listFails = true
	assertQueueUnknown(t, s, admin)
}

func TestQueueListDoesNotOverrideKnownRefill(t *testing.T) {
	world := newEximWorld(t)
	world.add(qMid, worldMessage{sender: "sender@example.com"})
	s, admin, _ := queueServer(t, world)
	queueSnapshot(time.Now())
	world.mu.Lock()
	delete(world.queue, qMid)
	world.mu.Unlock()
	queueSnapshot(time.Now())
	world.add(qNew, worldMessage{sender: "sender@example.com"})
	if got := queueSnapshot(time.Now()); got.Size != 1 || !got.DetailUnavailable {
		t.Fatalf("refilled snapshot = %+v", got)
	}
	if got := getQueueList(t, s, ""); got.Unavailable || !slices.Equal(got.ids(), []string{qNew}) || *got.Queued != 1 {
		t.Errorf("list after the refill = %v (queued %v, unavailable %v), want %s and not the empty listing", got.ids(), got.Queued, got.Unavailable, qNew)
	}
	if len(admin.reasons) != 1 {
		t.Errorf("msglog reads = %v, want the refilled page's one", admin.reasons)
	}
}

// The overview's count can show mail queued since an empty listing that is
// not due again for up to a minute. The list must show that mail at once,
// not answer that the queue is unknown while the card shows its size.
func TestQueueListListsAtOnceAfterEmptyQueueRefills(t *testing.T) {
	world := newEximWorld(t)
	s, _, _ := queueServer(t, world)
	if got := getQueueList(t, s, ""); got.Unavailable || *got.Queued != 0 {
		t.Fatalf("initial list = %+v, want a known empty queue", got)
	}
	world.add(qOld, worldMessage{sender: "sender@example.com", recipients: []string{"rcpt@example.net"}})
	world.add(qMid, worldMessage{sender: "sender@example.com", recipients: []string{"rcpt@example.net"}})
	if q := queueSnapshot(time.Now()); q.Size != 2 || q.Unavailable {
		t.Fatalf("snapshot = %+v, want a count of 2", q)
	}

	got := getQueueList(t, s, "")
	if got.Unavailable || !slices.Equal(got.ids(), []string{qOld, qMid}) || *got.Queued != 2 {
		t.Fatalf("list after the count rose = %v (queued %v, unavailable %v), want both messages", got.ids(), got.Queued, got.Unavailable)
	}
	if n := len(world.runs("-bp")); n != 2 {
		t.Errorf("full listings = %d, want the first and one more for the refill", n)
	}
}

// The extra listing runs once per refill of an empty queue, however many
// requests follow and whether or not it succeeds, so requests cannot turn
// it into a listing each.
func TestQueueListRefillListsOnce(t *testing.T) {
	world := newEximWorld(t)
	s, admin, _ := queueServer(t, world)
	getQueueList(t, s, "")
	world.add(qMid, worldMessage{sender: "sender@example.com", recipients: []string{"rcpt@example.net"}})
	world.listFails = true
	queueSnapshot(time.Now())
	for i := 0; i < 3; i++ {
		assertQueueUnknown(t, s, admin)
		queueSnapshot(time.Now())
	}
	if n := len(world.runs("-bp")); n != 2 {
		t.Errorf("full listings = %d, want the first and one failed refill listing", n)
	}

	// A refill seen after a good listing also lists once.
	world = newEximWorld(t)
	s, _, _ = queueServer(t, world)
	getQueueList(t, s, "")
	world.add(qMid, worldMessage{sender: "sender@example.com", recipients: []string{"rcpt@example.net"}})
	queueSnapshot(time.Now())
	for i := 0; i < 3; i++ {
		if got := getQueueList(t, s, ""); !slices.Equal(got.ids(), []string{qMid}) {
			t.Fatalf("request %d: list = %v, want %s", i, got.ids(), qMid)
		}
		queueSnapshot(time.Now())
	}
	if n := len(world.runs("-bp")); n != 2 {
		t.Errorf("full listings = %d, want the first and one for the refill", n)
	}
}

func TestQueueReasonCacheHasSizeBound(t *testing.T) {
	world := newEximWorld(t)
	s, admin, _ := queueServer(t, world)
	now := time.Now()
	for i := 0; i < queueListMaxLimit*3; i++ {
		id := fmt.Sprintf("1tAbCd-%06d-Ab", i)
		items := s.pageReasons(now.Add(time.Duration(i)*time.Millisecond), []intel.QueueMessage{{ID: id}})
		if len(items) != 1 || items[0].ID != id {
			t.Fatalf("wrong page: %+v", items)
		}
		if len(s.queueReasons) > queueListMaxLimit {
			t.Fatalf("cached %d reasons, want at most one maximum-sized page (%d)", len(s.queueReasons), queueListMaxLimit)
		}
	}
	if len(admin.reasons) != queueListMaxLimit*3 {
		t.Fatal("not every requested reason was read")
	}
}

func TestQueueReasonCacheRetainsTheCurrentPage(t *testing.T) {
	world := newEximWorld(t)
	s, admin, _ := queueServer(t, world)
	now := time.Now()
	msgs := make([]intel.QueueMessage, queueListMaxLimit)
	for i := range msgs {
		msgs[i].ID = fmt.Sprintf("1tAbCd-%06d-Ab", i)
	}
	s.pageReasons(now, msgs)
	// Half the next page is already cached, all with the same read time.
	for i := 0; i < len(msgs)/2; i++ {
		msgs[i].ID = fmt.Sprintf("1tAbCd-%06d-Ab", i+queueListMaxLimit)
	}
	s.pageReasons(now, msgs)
	s.pageReasons(now, msgs)
	if len(admin.reasons) != queueListMaxLimit*3/2 || len(s.queueReasons) != queueListMaxLimit {
		t.Errorf("reads = %d, cached = %d; want only new page members read and the full page retained", len(admin.reasons), len(s.queueReasons))
	}
}
