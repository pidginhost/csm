package checks

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/modsec"
	"github.com/pidginhost/csm/internal/platform"
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

// The same text can be an error-log prefix or a client-controlled audit Host.
// Select the interpretation from the configured source, never from that text.
func modsecAuditIsErrorLog(path string, cfg *config.Config) bool {
	path = filepath.Clean(path)
	if cfg.ModSecErrorLog != "" && filepath.Clean(cfg.ModSecErrorLog) == path {
		return true
	}
	for _, candidate := range platform.Detect().ErrorLogPaths {
		if filepath.Clean(candidate) == path {
			return true
		}
	}
	return false
}

// readModSecDenials returns the recent denials of each address and the
// newest of them with a recorded time, named in the file's stream.
func readModSecDenials(ctx context.Context, path string, errorLog bool) (map[string]int, map[string]scanRecord, bool) {
	f, err := osFS.Open(path)
	if err != nil {
		return nil, nil, false
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return nil, nil, false
	}

	modsecAuditReader.Lock()
	defer modsecAuditReader.Unlock()
	now := time.Now()
	r := &modsecAuditReader
	start := int64(0)
	if r.path == path && r.parser.errorLog == errorLog && r.info != nil && os.SameFile(r.info, info) && r.follow.Offset > 0 {
		start, _, err = chooseStart(f, r.follow, info.Size())
		if err != nil {
			r.info = nil
			return nil, nil, false
		}
	}
	if start == 0 {
		r.parser = modsecAuditParser{errorLog: errorLog}
	}
	// A partially advanced parser must never be paired with the old cursor.
	r.info = nil
	snapshot := followState{Offset: start}
	if err = fillIdentity(f, &snapshot, info.Size()); err != nil {
		return nil, nil, false
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
		lineStart := consumed
		line, truncated, readErr := readBoundedLineLog(br, maxLogLineBytes)
		if readErr == io.EOF {
			// Do not interpret an unfinished write. Resume before this line.
			break
		}
		if readErr != nil {
			return nil, nil, false
		}
		pos, seekErr := src.Seek(0, io.SeekCurrent)
		if seekErr != nil {
			return nil, nil, false
		}
		consumed = start + pos - int64(br.Buffered())
		if truncated {
			line = ""
		}
		r.parser.feed(syslogRecord{text: trimLogLineEnding(line), offset: lineStart}, truncated)
	}
	// A copytruncate during the read must not attach old framing to new bytes.
	head, err := fpAt(f, 0, int64(snapshot.HeadLen))
	if err != nil || head != snapshot.HeadFP {
		return nil, nil, false
	}
	next := followState{Offset: consumed}
	if err = fillIdentity(f, &next, info.Size()); err != nil {
		return nil, nil, false
	}
	r.path, r.info, r.follow = path, info, next
	if cancelled {
		return nil, nil, info.Size() > 0
	}
	var stream string
	if id, ok := selfWriteIdentityFromFileInfo(info); ok {
		stream = alert.FileStream(id.Device, id.Inode)
	}
	eligible := r.parser.newestAt(now)
	newest := make(map[string]scanRecord, len(eligible))
	for ip, n := range eligible {
		n.stream = stream
		newest[ip] = n.scanRecord
	}
	return maps.Clone(r.parser.blocked), newest, info.Size() > 0
}

type modsecAuditParser struct {
	errorLog    bool
	line, start int64
	txID, txIP  string
	section     byte
	wantFirst   bool
	denied      bool
	// txRec is the open transaction's A-section header: the record its
	// client was read from, with the time the server wrote there.
	txRec scanRecord
	// Each slot belongs to a physical line, including oversized body lines.
	// Attribute a completed transaction to its A line so the recent window
	// never counts a transaction whose start has already aged out.
	recent  [modsecAuditTailLines]modsecDenial
	blocked map[string]int
}

type modsecDenial struct {
	ip string
	modsecNewest
}

type modsecNewest struct {
	scanRecord
	line int64
}

func (p *modsecAuditParser) feed(rec syslogRecord, truncated bool) {
	if p.blocked == nil {
		p.blocked = make(map[string]int)
	}
	line := rec.text
	p.line++
	slot := p.line % modsecAuditTailLines
	if ip := p.recent[slot].ip; ip != "" {
		p.blocked[ip]--
		if p.blocked[ip] == 0 {
			delete(p.blocked, ip)
		}
		p.recent[slot] = modsecDenial{}
	}
	if truncated {
		p.wantFirst = false
		return
	}
	if p.errorLog {
		if ip, denied := modsecErrorLogDenial(line); denied {
			at, _ := modsec.ErrorLogTime(line)
			p.record(ip, p.line, scanned(rec, at))
		}
		return
	}
	id, section, boundary := modsecSectionBoundary(line)
	if p.txID == "" {
		if boundary {
			if section == 'A' {
				p.txID, p.txIP, p.txRec, p.section = id, "", scanRecord{}, 'A'
				p.start, p.wantFirst, p.denied = p.line, true, false
			}
			return
		}
		if ip, at, denied := modsecLineDenial(line); denied {
			p.record(ip, p.line, scanned(rec, at))
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
				p.record(p.txIP, p.start, p.txRec)
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
			p.txRec = scanned(rec, modsecAuditHeaderTime(line))
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

func (p *modsecAuditParser) record(ip string, line int64, r scanRecord) {
	if p.line-line < modsecAuditTailLines {
		p.recent[line%modsecAuditTailLines] = modsecDenial{ip, modsecNewest{r, line}}
		p.blocked[ip]++
	}
}

// Eligibility is relative to this scan, not the first read. Keeping the
// record with its counted line makes cached reads agree with a full replay
// as the clock advances or moves back, without retaining request text.
func (p *modsecAuditParser) newestAt(now time.Time) map[string]modsecNewest {
	newest := make(map[string]modsecNewest)
	for i := range p.recent {
		d := &p.recent[i]
		if d.at.IsZero() || d.at.After(now) {
			continue
		}
		if cur, ok := newest[d.ip]; !ok || d.line > cur.line {
			newest[d.ip] = d.modsecNewest
		}
	}
	return newest
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
		` \[(` + modsecIndexDate + `\.[0-9]{6} [+-][0-9]{4})\] ` + modsecIndexQuoted + ` ([0-9]{3}) [0-9-]+ ` +
		modsecIndexQuoted + ` ` + modsecIndexQuoted + ` ` + modsecIndexWord + ` ` + modsecIndexQuoted + modsecIndexEnd)
	modsecIndexV3 = regexp.MustCompile(`^` + modsecIndexWord + ` (` + modsecIndexWord + `) ` + modsecIndexWord +
		` \[(` + modsecIndexDate + ` [+-][0-9]{4})\] ` + modsecIndexQuoted + ` ([0-9]{3}) [0-9-]+ ` +
		modsecIndexWord + ` ` + modsecIndexQuoted + ` ` + modsecIndexWord + ` ` + modsecIndexWord + modsecIndexEnd)
)

// modsecLineDenial reads a one-line audit record: the client, the time the
// server recorded and whether the request was denied. The time comes from
// its fixed place in the validated grammar, never from client text.
func modsecLineDenial(line string) (string, time.Time, bool) {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "{") {
		var record struct {
			Transaction struct {
				ClientIP    string          `json:"client_ip"`
				TimeStamp   json.RawMessage `json:"time_stamp"`
				Interrupted bool            `json:"is_interrupted"`
				Response    struct {
					Status int `json:"http_code"`
				} `json:"response"`
			} `json:"transaction"`
		}
		if json.Unmarshal([]byte(line), &record) != nil {
			return "", time.Time{}, false
		}
		ip := net.ParseIP(record.Transaction.ClientIP)
		if ip == nil {
			return "", time.Time{}, false
		}
		// Unknown timestamp metadata must not discard a legacy denial.
		var stamp string
		var at time.Time
		if json.Unmarshal(record.Transaction.TimeStamp, &stamp) == nil {
			// libmodsecurity writes ctime in the server's local time.
			at, _ = time.ParseInLocation("Mon Jan 2 15:04:05 2006", stamp, time.Local)
		}
		return ip.String(), at, record.Transaction.Response.Status == 403 || record.Transaction.Interrupted
	}
	for _, re := range []*regexp.Regexp{modsecIndexV2, modsecIndexV3} {
		if fields := re.FindStringSubmatch(line); fields != nil {
			ip := net.ParseIP(fields[1])
			if ip == nil {
				return "", time.Time{}, false
			}
			at := modsecAuditTime(fields[2])
			return ip.String(), at, fields[3] == "403"
		}
	}
	return "", time.Time{}, false
}

func modsecAuditTime(stamp string) time.Time {
	at, err := time.Parse("02/Jan/2006:15:04:05 -0700", stamp)
	if err != nil {
		return time.Time{}
	}
	// Go accepts overflowing zone hours and minutes and normalizes them.
	// Those are not server timestamps and cannot date admission evidence.
	zone := stamp[len(stamp)-5:]
	if zone[1:3] > "23" || zone[3:] > "59" {
		return time.Time{}
	}
	return at
}

func modsecErrorLogDenial(line string) (string, bool) {
	// An error-log line: the action opens the message after the module
	// marker, and the client comes only from the server-written prefix.
	if msg, _ := modsec.ErrorLogMessage(line); strings.HasPrefix(msg, "Access denied with code ") {
		ip := modsec.ErrorLogClientIP(line)
		return ip, ip != ""
	}
	return "", false
}
