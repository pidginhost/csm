package webui

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/emailav"
	"github.com/pidginhost/csm/internal/mailfwd/intel"
	"github.com/pidginhost/csm/internal/systemdrun"
	"github.com/pidginhost/csm/internal/yara"
)

type emailStatsResponse struct {
	QueueSize int `json:"queue_size"`
	// QueueUnavailable marks queue_size as meaningless because the depth could
	// not be read. Without it a failed probe looks like an empty queue.
	QueueUnavailable bool `json:"queue_unavailable"`
	QueueWarn        int  `json:"queue_warn"`
	QueueCrit        int  `json:"queue_crit"`
	FrozenCount      int  `json:"frozen_count"`
	// OldestAgeSeconds is the age of the oldest queued message; left out
	// when the queue is empty or could not be read.
	OldestAgeSeconds *int             `json:"oldest_age_seconds,omitempty"`
	SMTPBlock        bool             `json:"smtp_block"`
	SMTPAllowUsers   []string         `json:"smtp_allow_users"`
	SMTPPorts        []int            `json:"smtp_ports"`
	PortFlood        []portFloodEntry `json:"port_flood"`
	TopSenders       []senderEntry    `json:"top_senders"`
}

type portFloodEntry struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Hits    int    `json:"hits"`
	Seconds int    `json:"window_seconds"`
}

type senderEntry struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

func (s *Server) apiEmailStats(w http.ResponseWriter, _ *http.Request) {
	cfg := s.liveCfg()
	resp := emailStatsResponse{
		QueueWarn: cfg.Thresholds.MailQueueWarn,
		QueueCrit: cfg.Thresholds.MailQueueCrit,
	}

	q := queueSnapshot(time.Now())
	resp.QueueSize, resp.QueueUnavailable = q.Size, q.Unavailable
	resp.FrozenCount, resp.OldestAgeSeconds = q.Frozen, q.OldestAgeSeconds

	// Firewall config
	fw := cfg.Firewall
	resp.SMTPBlock = fw.SMTPBlock
	resp.SMTPAllowUsers = fw.SMTPAllowUsers
	if resp.SMTPAllowUsers == nil {
		resp.SMTPAllowUsers = []string{}
	}
	resp.SMTPPorts = fw.SMTPPorts
	if resp.SMTPPorts == nil {
		resp.SMTPPorts = []int{}
	}

	// Port flood rules for SMTP ports only
	smtpPorts := map[int]bool{25: true, 465: true, 587: true}
	for _, pf := range fw.PortFlood {
		if smtpPorts[pf.Port] {
			resp.PortFlood = append(resp.PortFlood, portFloodEntry{
				Port:    pf.Port,
				Proto:   pf.Proto,
				Hits:    pf.Hits,
				Seconds: pf.Seconds,
			})
		}
	}
	if resp.PortFlood == nil {
		resp.PortFlood = []portFloodEntry{}
	}

	// Top senders from exim_mainlog
	resp.TopSenders = topMailSenders(500, 10)
	if resp.TopSenders == nil {
		resp.TopSenders = []senderEntry{}
	}

	writeJSON(w, resp)
}

// apiEmailQuarantineList handles GET /api/v1/email/quarantine and returns all
// quarantined email messages, or an empty array if the quarantine is not configured.
func (s *Server) apiEmailQuarantineList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	quarantine := s.emailQuarantineHandle()
	if quarantine == nil {
		writeAll(w, []emailav.QuarantineMetadata{})
		return
	}
	msgs, err := quarantine.ListMessages()
	if err != nil {
		writeJSONError(w, "Failed to list quarantine", http.StatusInternalServerError)
		return
	}
	writeAll(w, msgs)
}

// apiEmailQuarantineAction handles GET, POST (release), and DELETE operations on
// individual quarantined messages at /api/v1/email/quarantine/{msgID}.
func (s *Server) apiEmailQuarantineAction(w http.ResponseWriter, r *http.Request) {
	// Extract everything after the prefix, e.g. "abc123" or "abc123/release".
	tail := strings.TrimPrefix(r.URL.Path, "/api/v1/email/quarantine/")
	if tail == "" {
		writeJSONError(w, "Missing message ID", http.StatusBadRequest)
		return
	}

	parts := strings.SplitN(tail, "/", 2)
	msgID := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}

	if err := validateEximMessageID(msgID); err != nil {
		writeJSONError(w, "Invalid message ID: "+err.Error(), http.StatusBadRequest)
		return
	}

	quarantine := s.emailQuarantineHandle()
	if quarantine == nil {
		writeJSONError(w, "Email quarantine not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if action != "" {
			writeJSONError(w, "Unknown action", http.StatusBadRequest)
			return
		}
		meta, err := quarantine.GetMessage(msgID)
		if err != nil {
			writeJSONError(w, "Message not found", http.StatusNotFound)
			return
		}
		writeJSON(w, meta)

	case http.MethodPost:
		if action != "release" {
			writeJSONError(w, "Unknown action; use /release", http.StatusBadRequest)
			return
		}
		if err := quarantine.ReleaseMessage(msgID); err != nil {
			writeJSONError(w, "Failed to release message: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.auditLog(r, "email_quarantine_release", msgID, "released to the mail queue")
		writeOK(w, map[string]interface{}{"message_id": msgID})

	case http.MethodDelete:
		if action != "" {
			writeJSONError(w, "Unknown action", http.StatusBadRequest)
			return
		}
		if err := quarantine.DeleteMessage(msgID); err != nil {
			writeJSONError(w, "Failed to delete message: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.auditLog(r, "email_quarantine_delete", msgID, "deleted permanently")
		writeOK(w, map[string]interface{}{"message_id": msgID})

	default:
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Seams so the AV status handler can be tested without a live clamd.
var (
	resolveClamdSocket   = config.ResolveClamdSocket
	clamdSocketAvailable = func(path string) bool {
		return emailav.NewClamdScanner(path).Available()
	}
)

type emailAVStatusResponse struct {
	Enabled        bool   `json:"enabled"`
	ClamdAvailable bool   `json:"clamd_available"`
	ClamdSocket    string `json:"clamd_socket"`
	YaraXAvailable bool   `json:"yarax_available"`
	YaraXRuleCount int    `json:"yarax_rule_count"`
	WatcherMode    string `json:"watcher_mode"`
	Quarantined    int    `json:"quarantined"`
}

// apiEmailAVStatus handles GET /api/v1/email/av/status and returns the current
// state of the email AV subsystem (ClamAV, YARA-X, quarantine count, watcher mode).
func (s *Server) apiEmailAVStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := s.liveCfg()
	resp := emailAVStatusResponse{
		Enabled: cfg.EmailAV.Enabled,
	}

	// ClamAV availability. Resolve the socket the same way the daemon's
	// scanner does: when the configured path is not answering the daemon
	// falls back to a discovered one and mail really is being scanned, so
	// probing the configured path here would report the subsystem down over
	// a working scanner. Report the socket actually in use, not the stale
	// setting, or the page sends the operator after the wrong thing.
	clamdSocket, _ := resolveClamdSocket(cfg.EmailAV.ClamdSocket)
	if clamdSocket == "" {
		// Nothing configured and nothing discovered: name the documented
		// default so the card points somewhere rather than showing a blank.
		clamdSocket = config.DefaultClamdSocket
	}
	resp.ClamdSocket = clamdSocket
	resp.ClamdAvailable = clamdSocketAvailable(clamdSocket)

	// YARA-X availability and rule count. Active() covers both the
	// in-process scanner and the out-of-process worker so this card
	// reports the real rule count under either backend.
	resp.YaraXAvailable = yara.Available()
	if b := yara.Active(); b != nil {
		resp.YaraXRuleCount = b.RuleCount()
	}

	// Watcher mode (set by daemon on startup).
	resp.WatcherMode = s.emailAVMode()
	if resp.WatcherMode == "" {
		resp.WatcherMode = "disabled"
	}

	// Count of currently quarantined messages.
	if quarantine := s.emailQuarantineHandle(); quarantine != nil {
		msgs, err := quarantine.ListMessages()
		if err == nil {
			resp.Quarantined = len(msgs)
		}
	}

	writeJSON(w, resp)
}

// eximLookPath and eximRun are injection points so tests can drive the queue
// probes without a live exim.
var (
	eximLookPath = exec.LookPath
	eximRun      = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		// #nosec G204 -- name is the resolved systemd-run path or the fixed Exim command.
		return exec.CommandContext(ctx, name, args...).Output()
	}
)

// runExim executes an exim query as a transient unit forked by PID 1. The web
// server runs inside csm.service's ProtectSystem=strict sandbox, where /var/log
// is read-only; exim opens its main log for append even for a read-only query
// and aborts when it cannot, so a direct call returns nothing at all.
func runExim(timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return systemdrun.Run(ctx, eximLookPath, eximRun, systemdrun.Options{
		Pipe:       true,
		RuntimeMax: timeout,
	}, "exim", args...)
}

// eximQueueSize returns the current Exim mail queue count. The second result is
// false when the depth could not be read: reporting zero there is
// indistinguishable from a healthy empty queue.
func eximQueueSize() (int, bool) {
	out, err := runExim(5*time.Second, "-bpc")
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0, false
	}
	return n, true
}

// eximQueueDetails lists the queue with `exim -bp`, oldest first. ok is false
// when the listing could not be read or parsed.
func eximQueueDetails() ([]intel.QueueMessage, bool) {
	out, err := runExim(10*time.Second, "-bp")
	if err != nil {
		return nil, false
	}
	msgs, err := intel.ParseQueueList(out)
	if err != nil {
		return nil, false
	}
	sort.SliceStable(msgs, func(i, j int) bool {
		if !msgs[i].Arrived.Equal(msgs[j].Arrived) {
			return msgs[i].Arrived.Before(msgs[j].Arrived)
		}
		return msgs[i].ID < msgs[j].ID
	})
	return msgs, true
}

// emailQueueState is the live queue the Email page shows.
type emailQueueState struct {
	Size int `json:"size"`
	// Unavailable marks size as meaningless because the depth could not be
	// read.
	Unavailable bool `json:"unavailable"`
	Warn        int  `json:"warn"`
	Crit        int  `json:"crit"`
	Frozen      int  `json:"frozen"`
	// OldestAgeSeconds is left out when the queue is empty, holds no dated
	// message, or the detail is unavailable.
	OldestAgeSeconds *int `json:"oldest_age_seconds,omitempty"`
	// DetailUnavailable marks frozen and oldest as unknown: no listing has
	// succeeded within queueDetailMaxAge.
	DetailUnavailable bool `json:"detail_unavailable"`
}

const (
	// queueDetailTTL spaces queue listings. exim -bp reads every queued
	// message, which takes seconds on a deep queue, while the Email page
	// polls; the depth from exim -bpc stays live.
	queueDetailTTL = time.Minute
	// queueDetailMaxAge is how long the last good listing is served while
	// newer ones fail. A deep queue is when listings time out and when a
	// stale frozen count misleads most.
	queueDetailMaxAge = 10 * time.Minute
)

// queueDetail caches the queue listing the overview and the queue list share.
// Its lock is held while a listing runs, so concurrent polls wait for one
// listing instead of each starting their own.
var queueDetail struct {
	sync.Mutex
	state queueDetailState
}

type queueDetailState struct {
	tried  time.Time // last listing attempt
	listed time.Time // last successful listing, or the empty count
	// emptied marks listed as an exim -bpc that found the queue empty
	// rather than a listing. The overview has no detail for mail queued
	// since; the queue list serves the empty queue.
	emptied bool
	msgs    []intel.QueueMessage // oldest first; never modified once stored
	frozen  int
	// oldestQueued is when the oldest listed message was queued, the age
	// the listing gave counted back from listed; zero when it gave none.
	oldestQueued time.Time
}

// refreshQueueListing lists the queue when the last attempt, failed or not,
// is queueDetailTTL old. The caller holds queueDetail.
func refreshQueueListing(now time.Time) {
	d := &queueDetail.state
	if !d.tried.IsZero() && now.Sub(d.tried) < queueDetailTTL {
		return
	}
	d.tried = now
	msgs, ok := eximQueueDetails()
	if !ok {
		return
	}
	*d = queueDetailState{tried: now, listed: now, msgs: msgs}
	oldest := -1
	for _, m := range msgs {
		if m.Frozen {
			d.frozen++
		}
		oldest = max(oldest, m.AgeSeconds)
	}
	if oldest >= 0 {
		d.oldestQueued = now.Add(-time.Duration(oldest) * time.Second)
	}
}

// staleQueueListing reports whether the cached listing is too old to serve.
// The caller holds queueDetail.
func staleQueueListing(now time.Time) bool {
	d := &queueDetail.state
	return d.listed.IsZero() || now.Sub(d.listed) > queueDetailMaxAge
}

// oldestQueuedSeconds ages the oldest listed message to now. The caller holds
// queueDetail.
func oldestQueuedSeconds(now time.Time) *int {
	d := &queueDetail.state
	if d.oldestQueued.IsZero() {
		return nil
	}
	// A request that waited on the lock can hold a now from before the
	// listing; age from the listing then, never below what it showed.
	at := now
	if at.Before(d.listed) {
		at = d.listed
	}
	secs := int(at.Sub(d.oldestQueued) / time.Second)
	return &secs
}

// expireQueueListing makes the next caller list the queue again, after an
// action changed it.
func expireQueueListing() {
	queueDetail.Lock()
	defer queueDetail.Unlock()
	queueDetail.state.tried = time.Time{}
}

// queueSnapshot reads the queue depth on every call and lists the queue at
// most once per queueDetailTTL, failed attempts included. Frozen and oldest
// come from the last good listing, with oldest aged to now, for up to
// queueDetailMaxAge; past that DetailUnavailable is set. An empty depth
// drops the listing, which describes mail that is gone. Only a failed depth
// marks the queue unavailable. The caller fills Warn and Crit.
func queueSnapshot(now time.Time) emailQueueState {
	size, ok := eximQueueSize()
	q := emailQueueState{Size: size, Unavailable: !ok}
	queueDetail.Lock()
	defer queueDetail.Unlock()
	d := &queueDetail.state
	if ok && size == 0 {
		*d = queueDetailState{tried: d.tried, listed: now, emptied: true}
		return q
	}
	refreshQueueListing(now)
	if d.emptied || staleQueueListing(now) {
		q.DetailUnavailable = true
		return q
	}
	q.Frozen = d.frozen
	q.OldestAgeSeconds = oldestQueuedSeconds(now)
	return q
}

// topMailSenders parses the last N lines of exim_mainlog and returns the
// top K sender domains by outbound message count.
func topMailSenders(tailLines, topK int) []senderEntry {
	f, err := os.Open("/var/log/exim_mainlog")
	if err != nil {
		return nil
	}
	defer f.Close()

	// Read tail of file
	info, _ := f.Stat()
	var data []byte
	if info != nil && info.Size() > 256*1024 {
		if _, err := f.Seek(-256*1024, 2); err != nil {
			return nil
		}
		data, _ = io.ReadAll(f)
	} else {
		data, _ = io.ReadAll(f)
	}

	lines := strings.Split(string(data), "\n")
	// Take last N lines
	if len(lines) > tailLines {
		lines = lines[len(lines)-tailLines:]
	}

	counts := make(map[string]int)
	for _, line := range lines {
		idx := strings.Index(line, " <= ")
		if idx < 0 {
			continue
		}
		rest := line[idx+4:]
		fields := strings.Fields(rest)
		if len(fields) < 1 {
			continue
		}
		sender := fields[0]
		atIdx := strings.LastIndex(sender, "@")
		if atIdx < 0 {
			continue
		}
		domain := sender[atIdx+1:]
		if domain == "" || sender == "<>" || strings.HasPrefix(sender, "cPanel") {
			continue
		}
		counts[domain]++
	}

	var entries []senderEntry
	for domain, count := range counts {
		entries = append(entries, senderEntry{Domain: domain, Count: count})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})
	if len(entries) > topK {
		entries = entries[:topK]
	}
	return entries
}
