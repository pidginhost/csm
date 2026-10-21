package webui

import (
	"net/http"
	"slices"
	"time"

	"github.com/pidginhost/csm/internal/mailstats"
)

const (
	emailRejectsDefaultLimit = 50
	emailRejectsMaxLimit     = 200
)

// contentRejectClasses are the rejects the message content earned. They
// are what class=content, the default, lists.
var contentRejectClasses = []mailstats.Class{mailstats.ClassSpam, mailstats.ClassMalware}

// rejectClasses resolves the class parameter: content, all (nil) or one
// class name. ok is false for anything else.
func rejectClasses(class string) (classes []mailstats.Class, ok bool) {
	switch class {
	case "content":
		return contentRejectClasses, true
	case "all":
		return nil, true
	}
	if c := mailstats.Class(class); slices.Contains(mailstats.Classes, c) {
		return []mailstats.Class{c}, true
	}
	return nil, false
}

// apiEmailRejects handles GET /api/v1/email/rejects: the newest rejects the
// mail decision counter keeps for from/to (default the last 24 h). Each
// entry names a sender and a recipient, so the route is admin only.
func (s *Server) apiEmailRejects(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	class := q.Get("class")
	if class == "" {
		class = "content"
	}
	classes, ok := rejectClasses(class)
	if !ok {
		writeJSONError(w, "Invalid class: use content, all or a reject class name", http.StatusBadRequest)
		return
	}
	limit := queryInt(r, "limit", emailRejectsDefaultLimit)
	if limit <= 0 || limit > emailRejectsMaxLimit {
		limit = emailRejectsDefaultLimit
	}
	now := time.Now()
	from, to, ok := historyRangeQuery(w, q, now.Add(-24*time.Hour), now)
	if !ok {
		return
	}
	if to.Before(from) {
		from, to = to, from
	}

	var items []mailstats.Reject
	if c := s.mailStatsCounter(); c != nil {
		items = c.Rejects(from, to, classes, limit)
	}
	writeItems(w, items, map[string]interface{}{
		"class":     class,
		"limit":     limit,
		"kept_days": int(mailstats.RingAge / (24 * time.Hour)),
	})
}
