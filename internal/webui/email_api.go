package webui

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/emailav"
	"github.com/pidginhost/csm/internal/yara"
)

type emailStatsResponse struct {
	QueueSize      int              `json:"queue_size"`
	QueueWarn      int              `json:"queue_warn"`
	QueueCrit      int              `json:"queue_crit"`
	FrozenCount    int              `json:"frozen_count"`
	OldestAge      string           `json:"oldest_age"`
	SMTPBlock      bool             `json:"smtp_block"`
	SMTPAllowUsers []string         `json:"smtp_allow_users"`
	SMTPPorts      []int            `json:"smtp_ports"`
	PortFlood      []portFloodEntry `json:"port_flood"`
	TopSenders     []senderEntry    `json:"top_senders"`
}

type portFloodEntry struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Hits    int    `json:"hits"`
	Seconds int    `json:"seconds"`
}

type senderEntry struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

func (s *Server) apiEmailStats(w http.ResponseWriter, _ *http.Request) {
	resp := emailStatsResponse{
		QueueWarn: s.cfg.Thresholds.MailQueueWarn,
		QueueCrit: s.cfg.Thresholds.MailQueueCrit,
	}

	// Live queue size and frozen/oldest via exim
	resp.QueueSize = eximQueueSize()
	resp.FrozenCount, resp.OldestAge = eximQueueDetails()

	// Firewall config
	fw := s.cfg.Firewall
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
	if s.emailQuarantine == nil {
		writeJSON(w, []emailav.QuarantineMetadata{})
		return
	}
	msgs, err := s.emailQuarantine.ListMessages()
	if err != nil {
		writeJSONError(w, "Failed to list quarantine", http.StatusInternalServerError)
		return
	}
	if msgs == nil {
		msgs = []emailav.QuarantineMetadata{}
	}
	writeJSON(w, msgs)
}

// apiEmailQuarantineAction handles GET, POST (release), and DELETE operations on
// individual quarantined messages at /api/v1/email/quarantine/{msgID}.
func (s *Server) apiEmailQuarantineAction(w http.ResponseWriter, r *http.Request) {
	// Extract everything after the prefix, e.g. "abc123" or "abc123/release"
	tail := strings.TrimPrefix(r.URL.Path, "/api/v1/email/quarantine/")
	if tail == "" {
		writeJSONError(w, "Missing message ID", http.StatusBadRequest)
		return
	}

	parts := strings.SplitN(tail, "/", 2)
	msgID := filepath.Base(parts[0]) // sanitize path traversal
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}

	if msgID == "" || msgID == "." {
		writeJSONError(w, "Invalid message ID", http.StatusBadRequest)
		return
	}

	if s.emailQuarantine == nil {
		writeJSONError(w, "Email quarantine not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		meta, err := s.emailQuarantine.GetMessage(msgID)
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
		if err := s.emailQuarantine.ReleaseMessage(msgID); err != nil {
			writeJSONError(w, "Failed to release message: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"status": "released", "message_id": msgID})

	case http.MethodDelete:
		if err := s.emailQuarantine.DeleteMessage(msgID); err != nil {
			writeJSONError(w, "Failed to delete message: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"status": "deleted", "message_id": msgID})

	default:
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

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

	resp := emailAVStatusResponse{
		Enabled: s.cfg.EmailAV.Enabled,
	}

	// ClamAV availability - probe the configured socket.
	clamdSocket := s.cfg.EmailAV.ClamdSocket
	if clamdSocket == "" {
		clamdSocket = "/var/run/clamd.scan/clamd.sock"
	}
	resp.ClamdSocket = clamdSocket
	resp.ClamdAvailable = emailav.NewClamdScanner(clamdSocket).Available()

	// YARA-X availability and rule count.
	resp.YaraXAvailable = yara.Available()
	if gs := yara.Global(); gs != nil {
		resp.YaraXRuleCount = gs.RuleCount()
	}

	// Watcher mode (set by daemon on startup).
	resp.WatcherMode = s.emailAVWatcherMode
	if resp.WatcherMode == "" {
		resp.WatcherMode = "disabled"
	}

	// Count of currently quarantined messages.
	if s.emailQuarantine != nil {
		msgs, err := s.emailQuarantine.ListMessages()
		if err == nil {
			resp.Quarantined = len(msgs)
		}
	}

	writeJSON(w, resp)
}

// eximQueueSize returns the current Exim mail queue count, or 0 on error.
func eximQueueSize() int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "exim", "-bpc").Output()
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return n
}

// eximQueueDetails returns the frozen message count and the age of the oldest
// message in the queue. Uses `exim -bp` which lists all queued messages.
func eximQueueDetails() (frozen int, oldestAge string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "exim", "-bp").Output()
	if err != nil {
		return 0, ""
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "*** frozen ***") {
			frozen++
		}
		// First field of queue listing lines is the age (e.g., "4d", "15h", "30m")
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			age := fields[0]
			// Only consider lines where first field looks like an age
			if len(age) >= 2 && (age[len(age)-1] == 'd' || age[len(age)-1] == 'h' || age[len(age)-1] == 'm' || age[len(age)-1] == 's') {
				if oldestAge == "" {
					oldestAge = age // first entry is the oldest (queue sorted oldest first)
				}
			}
		}
	}
	return frozen, oldestAge
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
