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
	"time"
)

type emailStatsResponse struct {
	QueueSize      int              `json:"queue_size"`
	QueueWarn      int              `json:"queue_warn"`
	QueueCrit      int              `json:"queue_crit"`
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

	// Live queue size via exim -bpc
	resp.QueueSize = eximQueueSize()

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
		f.Seek(-256*1024, 2)
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
