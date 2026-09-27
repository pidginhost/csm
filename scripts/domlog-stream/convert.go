package main

import (
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/crawlid"
	"github.com/pidginhost/csm/internal/crawlreplay"
	"github.com/pidginhost/csm/internal/threatintel"
)

// maxLine is the follower's line bound (spec 6.1): a longer line is
// counted and skipped, never buffered whole.
const maxLine = 64 << 10

// pseudonyms derives salted identities. Sites and accounts use the same
// derivation as scripts/finding-stream, so one salt joins both streams.
type pseudonyms struct{ salt []byte }

func (p pseudonyms) mac(kind string, value []byte, n int) string {
	m := hmac.New(sha256.New, p.salt)
	m.Write([]byte(kind))
	m.Write([]byte{0})
	m.Write(value)
	return hex.EncodeToString(m.Sum(nil)[:n])
}

func (p pseudonyms) site(name string) string {
	return "dom-" + p.mac("domain", []byte(strings.ToLower(name)), 3) + ".example"
}

func (p pseudonyms) account(name string) string {
	return "acct-" + p.mac("account", []byte(strings.ToLower(name)), 3)
}

func (p pseudonyms) episode(name string) string {
	if name == "" {
		return ""
	}
	return "e-" + p.mac("crawl-episode", []byte(name), 8)
}

func (p pseudonyms) binding(b crawlid.Binding) string {
	return "b-" + p.mac("crawl-binding", []byte(b), 8)
}

func (p pseudonyms) key(k crawlid.Key) string {
	return "k-" + p.mac("crawl-key", k.Encode(), 8)
}

// siteCoverage is what the manifest says about one site's logs.
type siteCoverage struct {
	Site            string             `json:"site"`
	Account         string             `json:"account"`
	Coverage        []crawlreplay.Span `json:"coverage"`
	Lines           int64              `json:"lines"`
	Oversized       int64              `json:"oversized"`
	Rejected        int64              `json:"rejected"`
	TimeInvalid     int64              `json:"time_invalid"`
	NoTarget        int64              `json:"no_target"`
	AttributionLoss int64              `json:"attribution_loss"`
	InvalidClient   int64              `json:"invalid_client"`
	Infrastructure  int64              `json:"infrastructure"`
	Records         int64              `json:"records"`
	Labels          map[string]int64   `json:"labels"`
}

// inputFile identifies one log copy by digest, never by path.
type inputFile struct {
	Site    string `json:"site"`
	Ordinal int    `json:"ordinal"`
	SHA256  string `json:"sha256"`
	Bytes   int64  `json:"bytes"`
}

type converter struct {
	inv    *inventory
	labels []labelRule
	ps     pseudonyms
	open   func(path string) (io.ReadCloser, error)
}

// convertSite streams one site's logs into record rows and returns its
// volume rows, coverage and input digests.
func (c *converter) convertSite(s inventorySite, records io.Writer) ([]crawlreplay.Volume, siteCoverage, []inputFile, error) {
	cov := siteCoverage{Site: c.ps.site(s.Name), Account: c.ps.account(s.Account), Labels: map[string]int64{}}
	volume := map[int64]*crawlreplay.Volume{}
	var inputs []inputFile
	var seq int64
	first, last := int64(-1), int64(-1)
	for ordinal, path := range s.Logs {
		f, err := c.open(path)
		if err != nil {
			return nil, siteCoverage{}, nil, errInput
		}
		digest := sha256.New()
		counted := &countingReader{r: io.TeeReader(f, digest)}
		lines, err := logReader(counted)
		if err != nil {
			f.Close()
			return nil, siteCoverage{}, nil, errInput
		}
		err = eachLine(lines, func(line []byte, oversized bool) error {
			seq++
			cov.Lines++
			if oversized {
				cov.Oversized++
				return nil
			}
			rec, ok := checks.ParseCrawlLogLine(string(line), s.Aliases)
			switch {
			case !ok:
				cov.Rejected++
				return nil
			case !rec.TimeOK || rec.Time.Unix() <= 0:
				cov.TimeInvalid++
				return nil
			}
			row := c.row(s, &cov, rec, ordinal, seq)
			minute := row.T / 60
			v := volume[minute]
			if v == nil {
				v = &crawlreplay.Volume{Site: cov.Site, Minute: minute}
				volume[minute] = v
			}
			v.Lines++
			v.Bytes += int64(len(line)) + 1
			if rec.TargetInvalid || rec.TargetOverflow {
				v.NoTarget++
			}
			if row.Binding == "" {
				v.NoBinding++
			}
			if first < 0 || minute < first {
				first = minute
			}
			last = max(last, minute)
			cov.Records++
			cov.Labels[row.Label]++
			if writeErr := crawlreplay.WriteRow(records, row); writeErr != nil {
				return errOutputs
			}
			return nil
		})
		closeErr := f.Close()
		if err != nil {
			return nil, siteCoverage{}, nil, err
		}
		if closeErr != nil {
			return nil, siteCoverage{}, nil, errInput
		}
		inputs = append(inputs, inputFile{Site: cov.Site, Ordinal: ordinal, SHA256: hex.EncodeToString(digest.Sum(nil)), Bytes: counted.n})
	}
	if first >= 0 {
		cov.Coverage = []crawlreplay.Span{{From: first, To: last}}
	}
	rows := make([]crawlreplay.Volume, 0, len(volume))
	for _, v := range volume {
		rows = append(rows, *v)
	}
	slices.SortFunc(rows, func(a, b crawlreplay.Volume) int { return cmp.Compare(a.Minute, b.Minute) })
	return rows, cov, inputs, nil
}

// row builds one anonymized record; every string it sets is a pseudonym,
// a closed-set label or a validated bot identity.
func (c *converter) row(s inventorySite, cov *siteCoverage, rec checks.CrawlLogRecord, ordinal int, seq int64) crawlreplay.Record {
	row := crawlreplay.Record{T: rec.Time.Unix(), File: ordinal, Seq: seq, Site: cov.Site, Account: cov.Account, Status: rec.Status}
	switch rec.RefererClass {
	case checks.CrawlRefererMalformed:
		row.Referer = crawlreplay.RefMalformed
	case checks.CrawlRefererCrossSite:
		row.Referer = crawlreplay.RefCrossSite
	case checks.CrawlRefererSameSite:
		row.Referer = crawlreplay.RefSameSite
	}
	client, ok := c.client(rec)
	if !ok {
		cov.AttributionLoss++
	}
	if client.IsValid() {
		if containsAddr(c.inv.infra, client) {
			row.Infra = true
			cov.Infrastructure++
		}
		if b, bound := crawlid.BindingOf(client.String()); bound {
			row.Binding = c.ps.binding(b)
		}
	}
	var target crawlid.Target
	hasTarget := false
	if rec.TargetInvalid || rec.TargetOverflow {
		cov.NoTarget++
	} else if t, err := crawlid.ParseTarget(rec.Target, checks.CrawlTargetLimit); err == nil {
		target, hasTarget = t, true
		class := crawlid.Classify(rec.Method, t)
		switch {
		case class.Expensive:
			keys := crawlid.KeysFor([]byte(s.Name), class, t)
			row.Class, row.L2, row.L1 = crawlreplay.ClassExpensive, c.ps.key(keys[1]), c.ps.key(keys[2])
		case class.Dynamic:
			row.Class = crawlreplay.ClassDynamic
		}
	} else {
		cov.NoTarget++
	}
	if bot := threatintel.ClaimedBotFromUA(rec.UserAgent); bot != "" && botName.MatchString(bot) {
		row.Bot = bot
		row.BotRange = client.IsValid() && containsAddr(c.inv.bots[bot], client)
	}
	for _, rule := range c.labels {
		if rule.matches(s.Name, rec.Time, target, hasTarget) {
			row.Label, row.Episode = rule.Label, c.ps.episode(rule.Episode)
			break
		}
	}
	return row
}

// client returns the address a binding comes from: the direct peer, or the
// rightmost X-Forwarded-For entry a trusted proxy appended. ok is false
// when a trusted proxy's line has no usable forwarded address.
func (c *converter) client(rec checks.CrawlLogRecord) (netip.Addr, bool) {
	peer, err := netip.ParseAddr(rec.RemoteIP)
	if err != nil || peer.Zone() != "" {
		return netip.Addr{}, true
	}
	peer = peer.Unmap()
	if !containsAddr(c.inv.proxies, peer) {
		return peer, true
	}
	if rec.XFF == "" || rec.XFFUnusable {
		return netip.Addr{}, false
	}
	entry := rec.XFF[strings.LastIndexByte(rec.XFF, ',')+1:]
	a, err := netip.ParseAddr(strings.TrimSpace(entry))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

func (r labelRule) matches(site string, t time.Time, target crawlid.Target, hasTarget bool) bool {
	if r.Site != site || t.Before(r.From) || !t.Before(r.To) {
		return false
	}
	if r.Segment == nil && len(r.NamePrefixes) == 0 {
		return true
	}
	if !hasTarget || (r.Segment != nil && string(target.Segment) != *r.Segment) {
		return false
	}
	if len(r.NamePrefixes) == 0 {
		return true
	}
	for _, n := range target.Names {
		for _, p := range r.NamePrefixes {
			if bytes.HasPrefix(n, []byte(p)) {
				return true
			}
		}
	}
	return false
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// logReader transparently decompresses gzip copies.
func logReader(r io.Reader) (*bufio.Reader, error) {
	br := bufio.NewReaderSize(r, maxLine+2)
	head, err := br.Peek(2)
	if err == nil && head[0] == 0x1f && head[1] == 0x8b {
		gz, gzErr := gzip.NewReader(br)
		if gzErr != nil {
			return nil, gzErr
		}
		return bufio.NewReaderSize(gz, maxLine+2), nil
	}
	return br, nil
}

// eachLine calls fn for every line without its LF or CRLF. A line longer
// than maxLine is reported once as oversized and skipped to its end.
func eachLine(r *bufio.Reader, fn func(line []byte, oversized bool) error) error {
	for {
		line, err := r.ReadSlice('\n')
		oversized := false
		for errors.Is(err, bufio.ErrBufferFull) {
			oversized = true
			_, err = r.ReadSlice('\n')
		}
		if len(line) == 0 && errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return errInput
		}
		line = bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r"))
		if len(line) > maxLine {
			oversized = true
		}
		if fnErr := fn(line, oversized); fnErr != nil {
			return fnErr
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}
