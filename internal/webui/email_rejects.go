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

// permanentRejects counts the permanent rejects of every class in an
// overview: its rejects less its temporary ones.
func permanentRejects(t mailstats.Totals) map[mailstats.Class]int {
	out := make(map[mailstats.Class]int, len(mailstats.Classes))
	for _, c := range mailstats.Classes {
		out[c] = t.Rejects[c] - t.Temporary[c]
	}
	return out
}

// apiEmailRejects handles GET /api/v1/email/rejects: the newest rejects the
// mail decision counter keeps for from/to (see emailRange), and the
// permanent rejects of every class in the range. Each entry names a sender
// and a recipient, so the route is admin only.
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
	if limit <= 0 {
		limit = emailRejectsDefaultLimit
	}
	limit = min(limit, emailRejectsMaxLimit)
	from, to, ok := emailRange(w, q, time.Now())
	if !ok {
		return
	}

	var items []mailstats.Reject
	var totals mailstats.Totals
	if c := s.mailStatsCounter(); c != nil {
		items = c.Rejects(from, to, classes, limit)
		totals = c.Overview(from, to).Totals
	}
	writeItems(w, items, map[string]interface{}{
		"class":     class,
		"limit":     limit,
		"kept_days": int(mailstats.RingAge / (24 * time.Hour)),
		"totals":    permanentRejects(totals),
	})
}
