package checks

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"maps"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/pidginhost/csm/internal/modsec"
)

// A tail can consist entirely of client-controlled body text, including valid
// audit records. Only offset zero or a previously framed cursor is a safe start.
// Keep one reader for the selected platform path; rotation replays from zero.
var modsecAuditReader struct {
	sync.Mutex
	path   string
	info   os.FileInfo
	follow followState
	parser modsecAuditParser
}

func readModSecDenials(ctx context.Context, path string) (map[string]int, bool) {
	f, err := osFS.Open(path)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return nil, false
	}

	modsecAuditReader.Lock()
	defer modsecAuditReader.Unlock()
	r := &modsecAuditReader
	start := int64(0)
	if r.path == path && r.info != nil && os.SameFile(r.info, info) && r.follow.Offset > 0 {
		start, _, err = chooseStart(f, r.follow, info.Size())
		if err != nil {
			r.info = nil
			return nil, false
		}
	}
	if start == 0 {
		r.parser = modsecAuditParser{}
	}
	// A partially advanced parser must never be paired with the old cursor.
	r.info = nil
	snapshot := followState{Offset: start}
	if err = fillIdentity(f, &snapshot, info.Size()); err != nil {
		return nil, false
	}
	src := io.NewSectionReader(f, start, info.Size()-start)
	br := bufio.NewReaderSize(src, 64*1024)
	consumed := start
	cancelled := false
	for {
		if ctx.Err() != nil {
			// Large initial logs may need several scan budgets. Retain the
			// framed prefix, but never report its stale counts as current.
			cancelled = true
			break
		}
		line, truncated, readErr := readBoundedLineLog(br, maxLogLineBytes)
		if readErr == io.EOF {
			// Do not interpret an unfinished write. Resume before this line.
			break
		}
		if readErr != nil {
			return nil, false
		}
		pos, seekErr := src.Seek(0, io.SeekCurrent)
		if seekErr != nil {
			return nil, false
		}
		consumed = start + pos - int64(br.Buffered())
		if truncated {
			line = ""
		}
		r.parser.feed(trimLogLineEnding(line), truncated)
	}
	// A copytruncate during the read must not attach old framing to new bytes.
	head, err := fpAt(f, 0, int64(snapshot.HeadLen))
	if err != nil || head != snapshot.HeadFP {
		return nil, false
	}
	next := followState{Offset: consumed}
	if err = fillIdentity(f, &next, info.Size()); err != nil {
		return nil, false
	}
	r.path, r.info, r.follow = path, info, next
	if cancelled {
		return nil, info.Size() > 0
	}
	return maps.Clone(r.parser.blocked), info.Size() > 0
}

type modsecAuditParser struct {
	line, start int64
	txID, txIP  string
	section     byte
	wantFirst   bool
	denied      bool
	// Each slot belongs to a physical line, including oversized body lines.
	// Attribute a completed transaction to its A line so the recent window
	// never counts a transaction whose start has already aged out.
	recent  [modsecAuditTailLines]string
	blocked map[string]int
}

func (p *modsecAuditParser) feed(line string, truncated bool) {
	if p.blocked == nil {
		p.blocked = make(map[string]int)
	}
	p.line++
	slot := p.line % modsecAuditTailLines
	if ip := p.recent[slot]; ip != "" {
		p.blocked[ip]--
		if p.blocked[ip] == 0 {
			delete(p.blocked, ip)
		}
		p.recent[slot] = ""
	}
	if truncated {
		p.wantFirst = false
		return
	}
	id, section, boundary := modsecSectionBoundary(line)
	if p.txID == "" {
		if boundary {
			if section == 'A' {
				p.txID, p.txIP, p.section = id, "", 'A'
				p.start, p.wantFirst, p.denied = p.line, true, false
			}
			return
		}
		if ip, denied := modsecLineDenial(line); denied {
			p.record(ip, p.line)
		}
		return
	}
	if boundary {
		// Other IDs are body content. They cannot end this transaction,
		// suppress its denial, or erase another client's counts.
		if id != p.txID {
			return
		}
		if section == 'Z' {
			if p.denied && p.txIP != "" {
				p.record(p.txIP, p.start)
			}
			p.txID = ""
			return
		}
		p.section, p.wantFirst = section, true
		return
	}
	if p.wantFirst && strings.TrimSpace(line) != "" {
		p.wantFirst = false
		switch p.section {
		case 'A':
			p.txIP = modsecAuditClientIP(line)
		case 'F':
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.HasPrefix(fields[0], "HTTP/") && fields[1] == "403" {
				p.denied = true
			}
		}
	}
	if p.section == 'H' && (strings.HasPrefix(line, "Message: Access denied with code ") ||
		strings.HasPrefix(line, "ModSecurity: Access denied with code ")) {
		p.denied = true
	}
}

func (p *modsecAuditParser) record(ip string, line int64) {
	if p.line-line < modsecAuditTailLines {
		p.recent[line%modsecAuditTailLines] = ip
		p.blocked[ip]++
	}
}

const (
	modsecIndexWord   = `\S+`
	modsecIndexQuoted = `"(?:\\.|[^"\\\r\n])*"`
	modsecIndexDate   = `[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}`
	modsecIndexEnd    = ` ` + modsecIndexWord + ` [0-9]+ [0-9]+(?:\.[0-9]+)? md5:[0-9a-fA-F]{32}$`
)

var (
	// v2 writes a microsecond timestamp and two user columns; v3 writes
	// whole seconds and one. Validate the entire grammar so a malformed Host
	// cannot change dialect or fall through to an embedded [client] field.
	modsecIndexV2 = regexp.MustCompile(`^` + modsecIndexWord + ` (` + modsecIndexWord + `) ` + modsecIndexWord + ` ` + modsecIndexWord +
		` \[` + modsecIndexDate + `\.[0-9]{6} [+-][0-9]{4}\] ` + modsecIndexQuoted + ` ([0-9]{3}) [0-9-]+ ` +
		modsecIndexQuoted + ` ` + modsecIndexQuoted + ` ` + modsecIndexWord + ` ` + modsecIndexQuoted + modsecIndexEnd)
	modsecIndexV3 = regexp.MustCompile(`^` + modsecIndexWord + ` (` + modsecIndexWord + `) ` + modsecIndexWord +
		` \[` + modsecIndexDate + ` [+-][0-9]{4}\] ` + modsecIndexQuoted + ` ([0-9]{3}) [0-9-]+ ` +
		modsecIndexWord + ` ` + modsecIndexQuoted + ` ` + modsecIndexWord + ` ` + modsecIndexWord + modsecIndexEnd)
)

func modsecLineDenial(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "{") {
		var record struct {
			Transaction struct {
				ClientIP    string `json:"client_ip"`
				Interrupted bool   `json:"is_interrupted"`
				Response    struct {
					Status int `json:"http_code"`
				} `json:"response"`
			} `json:"transaction"`
		}
		if json.Unmarshal([]byte(line), &record) != nil {
			return "", false
		}
		ip := net.ParseIP(record.Transaction.ClientIP)
		if ip == nil {
			return "", false
		}
		return ip.String(), record.Transaction.Response.Status == 403 || record.Transaction.Interrupted
	}
	for _, re := range []*regexp.Regexp{modsecIndexV2, modsecIndexV3} {
		if fields := re.FindStringSubmatch(line); fields != nil {
			ip := net.ParseIP(fields[1])
			if ip == nil {
				return "", false
			}
			return ip.String(), fields[2] == "403"
		}
	}
	if strings.Contains(line, `] "`) {
		return "", false
	}
	// An error-log line: the action opens the message after the module
	// marker, and the client comes only from the server-written prefix.
	if msg, _ := modsec.ErrorLogMessage(line); strings.HasPrefix(msg, "Access denied with code ") {
		ip := modsec.ErrorLogClientIP(line)
		return ip, ip != ""
	}
	return "", false
}
