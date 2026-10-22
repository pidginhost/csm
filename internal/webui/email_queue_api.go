package webui

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/mailfwd/intel"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/systemdrun"
)

const (
	queueListDefaultLimit = 25
	queueListMaxLimit     = 100
	// queueReasonTTL is how long a message's msglog reason is reused.
	queueReasonTTL = time.Minute
	// queueUnavailableText answers the queue routes on hosts without exim.
	queueUnavailableText = "Mail queue is not available on this host"
)

// selectQueueAdmin picks the per-message queue executor. Only cPanel/exim is
// wired; other platforms answer the queue routes as unavailable.
func selectQueueAdmin() intel.QueueAdmin {
	if platform.Detect().IsCPanel() {
		return intel.NewEximQueueAdmin(platform.EximSpoolRoot, eximLookPath, eximRun)
	}
	return nil
}

// queueItem is a queued message with why it is stuck.
type queueItem struct {
	intel.QueueMessage
	Reason intel.StuckReason `json:"reason"`
}

// queueMessageDetail is one queued message with the last lines of its msglog.
type queueMessageDetail struct {
	intel.QueueMessage
	Reason intel.StuckReason `json:"reason"`
	Msglog []string          `json:"msglog"`
}

type cachedQueueReason struct {
	read   time.Time
	reason intel.StuckReason
}

// apiEmailQueueList handles GET /api/v1/email/queue: one page of the queue,
// oldest first, filtered by filter=all|frozen|backscatter and q (a sender or
// recipient substring). queued, frozen, backscatter and oldest_seconds
// describe the whole queue; total counts the matches; listed_at is when the
// listing ran. The listing is the cached one the overview uses, and msglogs
// are read only for the page.
func (s *Server) apiEmailQueueList(w http.ResponseWriter, r *http.Request) {
	if s.queueAdmin == nil {
		writeJSONError(w, queueUnavailableText, http.StatusServiceUnavailable)
		return
	}
	query := r.URL.Query()
	filter := query.Get("filter")
	switch filter {
	case "":
		filter = "all"
	case "all", "frozen", "backscatter":
	default:
		writeJSONError(w, "Invalid filter: use all, frozen or backscatter", http.StatusBadRequest)
		return
	}
	search := strings.ToLower(strings.TrimSpace(query.Get("q")))
	page := max(queryInt(r, "page", 1), 1)
	limit := queryInt(r, "limit", queueListDefaultLimit)
	if limit <= 0 {
		limit = queueListDefaultLimit
	}
	limit = min(limit, queueListMaxLimit)

	now := time.Now()
	queueDetail.Lock()
	if queueDetail.state.refill {
		// The card already counts mail queued since an empty listing; list
		// it now rather than answer that the queue is unknown until the
		// next listing is due.
		queueDetail.state.tried = time.Time{}
	}
	refreshQueueListing(now)
	stale := staleQueueListing(now)
	msgs, frozen, oldest, listed := queueDetail.state.msgs, queueDetail.state.frozen, oldestQueuedSeconds(now), queueDetail.state.listed
	queueDetail.Unlock()
	if stale {
		// No count goes out: any number here would read as a queue size.
		writeItems(w, []queueItem{}, map[string]interface{}{"page": page, "limit": limit, "unavailable": true})
		return
	}

	backscatter := 0
	var matched []intel.QueueMessage
	for _, m := range msgs {
		if m.Bounce {
			backscatter++
		}
		if queueMessageMatches(m, filter, search) {
			matched = append(matched, m)
		}
	}
	start := len(matched)
	if page-1 <= len(matched)/limit {
		start = min((page-1)*limit, len(matched))
	}
	end := min(start+limit, len(matched))

	extra := map[string]interface{}{
		"total":       len(matched),
		"queued":      len(msgs),
		"page":        page,
		"limit":       limit,
		"frozen":      frozen,
		"backscatter": backscatter,
		"unavailable": false,
		"listed_at":   listed.UTC(),
	}
	if oldest != nil {
		extra["oldest_seconds"] = *oldest
	}
	writeItems(w, s.pageReasons(now, matched[start:end]), extra)
}

func queueMessageMatches(m intel.QueueMessage, filter, search string) bool {
	if (filter == "frozen" && !m.Frozen) || (filter == "backscatter" && !m.Bounce) {
		return false
	}
	if search == "" || strings.Contains(strings.ToLower(m.Sender), search) {
		return true
	}
	for _, rcpt := range m.Recipients {
		if strings.Contains(strings.ToLower(rcpt), search) {
			return true
		}
	}
	return false
}

// pageReasons pairs each message of a list page with why it is stuck. A
// msglog is reused for queueReasonTTL while cached. The cache holds at most
// queueListMaxLimit reasons, retaining the current page before older pages.
func (s *Server) pageReasons(now time.Time, msgs []intel.QueueMessage) []queueItem {
	s.queueReasonMu.Lock()
	defer s.queueReasonMu.Unlock()
	for id, c := range s.queueReasons {
		if now.Sub(c.read) >= queueReasonTTL {
			delete(s.queueReasons, id)
		}
	}
	if s.queueReasons == nil {
		s.queueReasons = map[string]cachedQueueReason{}
	}
	pageIDs := make(map[string]bool, len(msgs))
	for _, m := range msgs {
		pageIDs[m.ID] = true
	}
	items := make([]queueItem, len(msgs))
	for i, m := range msgs {
		c, ok := s.queueReasons[m.ID]
		if !ok {
			if len(s.queueReasons) == queueListMaxLimit {
				var oldestID string
				var oldest time.Time
				for id, entry := range s.queueReasons {
					if !pageIDs[id] && (oldestID == "" || entry.read.Before(oldest)) {
						oldestID, oldest = id, entry.read
					}
				}
				delete(s.queueReasons, oldestID)
			}
			c.read = now
			c.reason, _ = s.msglogReason(m.ID)
			s.queueReasons[m.ID] = c
		}
		items[i] = queueItem{QueueMessage: m, Reason: queueReason(m, c.reason)}
	}
	return items
}

// msglogReason reads a message's msglog. A log CSM refuses to read, such as a
// symlink, is reported as unreadable rather than as no attempt.
func (s *Server) msglogReason(id string) (intel.StuckReason, []string) {
	reason, lines, err := s.queueAdmin.Reason(id)
	if err != nil {
		return intel.StuckReason{Class: "other", Text: "delivery log unreadable", Raw: err.Error()}, nil
	}
	return reason, lines
}

// queueReason corrects what the msglog cannot know: a message thawed since it
// froze is waiting for its next delivery attempt.
func queueReason(m intel.QueueMessage, r intel.StuckReason) intel.StuckReason {
	if r.Class == "frozen" && !m.Frozen {
		r.Class, r.Text = "retry_wait", "thawed, waiting for the next delivery attempt"
	}
	return r
}

// apiEmailQueueMessage handles GET /api/v1/email/queue/{id}: one queued
// message with all its undelivered recipients, why it is stuck and the last
// lines of its msglog, read live.
func (s *Server) apiEmailQueueMessage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !intel.ValidMessageID(id) {
		writeJSONError(w, "Invalid message ID", http.StatusBadRequest)
		return
	}
	if s.queueAdmin == nil {
		writeJSONError(w, queueUnavailableText, http.StatusServiceUnavailable)
		return
	}
	m, err := s.queueAdmin.Message(id)
	if errors.Is(err, intel.ErrNotQueued) {
		writeJSONError(w, "Message is not in the queue", http.StatusNotFound)
		return
	}
	if errors.Is(err, systemdrun.ErrUnavailable) {
		writeJSONError(w, "Reading the queue needs systemd-run: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		writeJSONError(w, "Failed to read the message from the queue: "+err.Error(), http.StatusInternalServerError)
		return
	}
	reason, lines := s.msglogReason(id)
	if lines == nil {
		lines = []string{}
	}
	writeJSON(w, queueMessageDetail{QueueMessage: m, Reason: queueReason(m, reason), Msglog: lines})
}

// apiEmailQueueAction handles POST /api/v1/email/queue/{id}/{action} for
// retry, bounce, delete and thaw. The answer carries the outcome the queue
// shows afterwards, and every attempt is audit-logged with it and with any
// error exim reported, including for work the queue shows done.
func (s *Server) apiEmailQueueAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, action := r.PathValue("id"), r.PathValue("action")
	if !intel.ValidMessageID(id) {
		writeJSONError(w, "Invalid message ID", http.StatusBadRequest)
		return
	}
	if !intel.ValidQueueAction(action) {
		writeJSONError(w, "Unknown action: use retry, bounce, delete or thaw", http.StatusBadRequest)
		return
	}
	if s.queueAdmin == nil {
		writeJSONError(w, queueUnavailableText, http.StatusServiceUnavailable)
		return
	}

	outcome, err := s.queueAdmin.Act(action, id)
	details := "outcome: " + outcome
	if err != nil {
		details += "; " + err.Error()
	}
	s.auditLog(r, "email_queue_"+action, id, details)
	s.queueReasonMu.Lock()
	delete(s.queueReasons, id)
	s.queueReasonMu.Unlock()
	expireQueueListing()

	switch {
	case outcome == intel.OutcomeGone:
		writeJSONStatus(w, http.StatusConflict, map[string]string{"error": "Message is no longer in the queue", "outcome": outcome})
	case outcome != intel.OutcomeUnchanged || err == nil:
		writeOK(w, map[string]interface{}{"outcome": outcome})
	case errors.Is(err, systemdrun.ErrUnavailable):
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "Queue actions need systemd-run: " + err.Error(), "outcome": outcome})
	default:
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "Queue action failed: " + err.Error(), "outcome": outcome})
	}
}
