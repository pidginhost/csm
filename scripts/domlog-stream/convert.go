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
	"hash"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
	"syscall"
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
// derivation as scripts/finding-stream, so one salt joins both streams. A
// pseudonym is a prefix of a keyed digest; the full digest of every
// prefix issued is kept, so two distinct names that share a prefix are
// refused instead of merged. Site and account pseudonyms keep
// finding-stream's 24-bit derivation, where such a collision is plausible;
// they and episode pseudonyms also go to the cross-bundle registry. Key and
// binding pseudonyms are 64 bits and stay out of it: a registry of every
// client and pattern would grow with all traffic ever converted.
type pseudonyms struct {
	digest func(kind string, value []byte) [sha256.Size]byte
	seen   map[string]map[uint64][sha256.Size]byte
	named  map[string]string // issued site, account and episode pseudonym -> full digest
}

// newPseudonyms derives with HMAC-SHA256 under salt unless digest is set.
func newPseudonyms(salt []byte, digest func(string, []byte) [sha256.Size]byte) *pseudonyms {
	if digest == nil {
		key := append([]byte(nil), salt...)
		digest = func(kind string, value []byte) [sha256.Size]byte { return saltedDigest(key, kind, value) }
	}
	return &pseudonyms{digest: digest, seen: map[string]map[uint64][sha256.Size]byte{}, named: map[string]string{}}
}

func saltedDigest(salt []byte, kind string, value []byte) [sha256.Size]byte {
	m := hmac.New(sha256.New, salt)
	m.Write([]byte(kind))
	m.Write([]byte{0})
	m.Write(value)
	var d [sha256.Size]byte
	copy(d[:], m.Sum(nil))
	return d
}

// name returns the hex prefix of value's digest, n bytes long, and the
// whole digest.
func (p *pseudonyms) name(kind string, value []byte, n int) (string, string, error) {
	d := p.digest(kind, value)
	var prefix uint64
	for _, b := range d[:n] {
		prefix = prefix<<8 | uint64(b)
	}
	seen := p.seen[kind]
	if seen == nil {
		seen = map[uint64][sha256.Size]byte{}
		p.seen[kind] = seen
	}
	if old, ok := seen[prefix]; ok && old != d {
		return "", "", errCollision
	}
	seen[prefix] = d
	return hex.EncodeToString(d[:n]), hex.EncodeToString(d[:]), nil
}

func (p *pseudonyms) site(name string) (string, error) {
	h, full, err := p.name("domain", []byte(strings.ToLower(name)), 3)
	out := "dom-" + h + ".example"
	p.named[out] = full
	return out, err
}

func (p *pseudonyms) account(name string) (string, error) {
	h, full, err := p.name("account", []byte(strings.ToLower(name)), 3)
	out := "acct-" + h
	p.named[out] = full
	return out, err
}

func (p *pseudonyms) episode(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	h, full, err := p.name("crawl-episode", []byte(name), 8)
	out := "e-" + h
	p.named[out] = full
	return out, err
}

func (p *pseudonyms) binding(b crawlid.Binding) (string, error) {
	h, _, err := p.name("crawl-binding", []byte(b), 8)
	return "b-" + h, err
}

func (p *pseudonyms) key(k crawlid.Key) (string, error) {
	h, _, err := p.name("crawl-key", k.Encode(), 8)
	return "k-" + h, err
}

// logFile is one open log copy.
type logFile interface {
	io.ReadCloser
	Stat() (os.FileInfo, error)
}

// openLog opens a log copy without following a symlink or blocking on a
// FIFO; convertSite then refuses anything but a regular file.
func openLog(path string) (logFile, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- operator-listed private log copy; symlinks refused
}

type converter struct {
	inv    *inventory
	labels []labelRule
	ps     *pseudonyms
	bots   *botEvidence // nil: no claim is verified
	open   func(path string) (logFile, error)
	now    time.Time
	// Every copy read so far, so no request is counted twice through a
	// second path, a hard link or a compressed duplicate.
	files   []os.FileInfo
	content map[string]bool
}

func newConverter(inv *inventory, labels []labelRule, ps *pseudonyms, now time.Time) *converter {
	return &converter{inv: inv, labels: labels, ps: ps, open: openLog, now: now, content: map[string]bool{}}
}

// Lost-line categories without a usable time, in the manifest's order.
const (
	lostOversized = iota
	lostRejected
	lostTimeInvalid
	lostTimeFuture
	lostIncomplete
	lostCategories
)

var lostNames = [lostCategories]string{crawlreplay.LossOversized, crawlreplay.LossRejected, crawlreplay.LossTimeInvalid,
	crawlreplay.LossTimeFuture, crawlreplay.LossIncomplete}

func lostCounter(sm *crawlreplay.SiteManifest, category int) *int64 {
	return [lostCategories]*int64{&sm.Oversized, &sm.Rejected, &sm.TimeInvalid, &sm.TimeFuture, &sm.Incomplete}[category]
}

// untimedRun gathers one input's lines without a usable time since its last
// timed line.
type untimedRun struct {
	input  int
	after  int64
	counts [lostCategories]int64
}

// close records the gathered lines as lying between the last timed line
// and before (0 at the end of the input).
func (u *untimedRun) close(sm *crawlreplay.SiteManifest, before int64) {
	for i, n := range u.counts {
		if n > 0 {
			sm.Untimed = append(sm.Untimed, crawlreplay.UntimedLoss{Input: u.input, Category: lostNames[i], After: u.after, Before: before, Lines: n})
		}
	}
	u.counts = [lostCategories]int64{}
	u.after = before
}

// convertSite streams one site's logs into record rows and returns its
// volume rows, manifest entry and inputs. Every line is a record or one
// counted refusal, and every byte read is in a volume row or unplaced.
func (c *converter) convertSite(s inventorySite, records io.Writer) ([]crawlreplay.Volume, crawlreplay.SiteManifest, []crawlreplay.Input, error) {
	site, siteErr := c.ps.site(s.Name)
	account, accountErr := c.ps.account(s.Account)
	if err := errors.Join(siteErr, accountErr); err != nil {
		return nil, crawlreplay.SiteManifest{}, nil, errCollision
	}
	sm := crawlreplay.SiteManifest{Site: site, Account: account, Labels: map[string]int64{}, Untimed: []crawlreplay.UntimedLoss{}}
	from, to := c.inv.Period.From.Unix(), c.inv.Period.To.Unix()
	volume := map[int64]*crawlreplay.Volume{}
	var inputs []crawlreplay.Input
	var seq int64
	for ordinal, path := range s.Logs {
		run := &untimedRun{input: ordinal}
		in := crawlreplay.Input{Site: sm.Site, Ordinal: ordinal}
		err := c.readInput(path, &in, func(l logLine) error {
			seq++
			sm.Lines++
			sm.Bytes += l.size
			lost := -1
			var rec checks.CrawlLogRecord
			switch {
			case !l.complete:
				lost = lostIncomplete
			case l.oversized:
				lost = lostOversized
			default:
				var ok bool
				rec, ok = checks.ParseCrawlLogLine(string(l.text), s.Aliases)
				switch {
				case !ok:
					lost = lostRejected
				case !rec.TimeOK || rec.Time.Unix() <= 0:
					lost = lostTimeInvalid
				case rec.Time.After(c.now):
					lost = lostTimeFuture
				}
			}
			if lost >= 0 {
				run.counts[lost]++
				*lostCounter(&sm, lost)++
				sm.UnplacedBytes += l.size
				return nil
			}
			// Any valid time bounds the untimed lines before it, even one
			// outside the period.
			t := rec.Time.Unix()
			run.close(&sm, t)
			if t < from || t >= to {
				sm.OutOfPeriod++
				sm.UnplacedBytes += l.size
				return nil
			}
			row, noTarget, rowErr := c.row(s, &sm, rec, ordinal, seq)
			if rowErr != nil {
				return rowErr
			}
			minute := t / 60
			v := volume[minute]
			if v == nil {
				v = &crawlreplay.Volume{Site: sm.Site, Minute: minute}
				volume[minute] = v
			}
			v.Lines++
			v.Bytes += l.size
			if noTarget {
				v.NoTarget++
			}
			if row.Binding == "" {
				v.NoBinding++
			}
			widen(&sm.Extent, minute)
			widen(&in.Extent, minute)
			sm.Records++
			sm.Labels[row.Label]++
			if writeErr := crawlreplay.WriteRow(records, row); writeErr != nil {
				return errOutputs
			}
			return nil
		})
		if err != nil {
			return nil, crawlreplay.SiteManifest{}, nil, err
		}
		run.close(&sm, 0)
		inputs = append(inputs, in)
	}
	rows := make([]crawlreplay.Volume, 0, len(volume))
	for _, v := range volume {
		rows = append(rows, *v)
	}
	slices.SortFunc(rows, func(a, b crawlreplay.Volume) int { return cmp.Compare(a.Minute, b.Minute) })
	return rows, sm, inputs, nil
}

func widen(extent **crawlreplay.Span, minute int64) {
	if *extent == nil {
		*extent = &crawlreplay.Span{From: minute, To: minute}
		return
	}
	(*extent).From, (*extent).To = min((*extent).From, minute), max((*extent).To, minute)
}

// readInput reads one copy through fn and records its digests. It refuses
// anything but a regular file that stayed unchanged while read and differs,
// by file identity and by decompressed content, from every copy before it.
func (c *converter) readInput(path string, in *crawlreplay.Input, fn func(logLine) error) error {
	f, err := c.open(path)
	if err != nil {
		return errInput
	}
	fail := func(err error) error {
		f.Close()
		return err
	}
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return fail(errInputIdentity)
	}
	for _, seen := range c.files {
		if os.SameFile(seen, before) {
			return fail(errInputIdentity)
		}
	}
	c.files = append(c.files, before)
	raw := sha256.New()
	// A live writer must not move EOF away indefinitely. Read only the
	// size we opened, then refuse any change to that snapshot.
	counted := &countingReader{r: io.TeeReader(io.LimitReader(f, before.Size()), raw)}
	lines, content, err := logReader(counted)
	if err != nil {
		return fail(errInput)
	}
	if err = eachLine(lines, fn); err != nil {
		return fail(err)
	}
	after, statErr := f.Stat()
	if closeErr := f.Close(); statErr != nil || closeErr != nil {
		return errInput
	}
	if counted.n != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) ||
		!sameInputChangeTime(before, after) {
		return errInputIdentity
	}
	in.SHA256, in.Bytes = hex.EncodeToString(raw.Sum(nil)), counted.n
	in.ContentSHA256, in.ContentBytes = hex.EncodeToString(content.h.Sum(nil)), content.n
	if in.ContentBytes > 0 {
		if c.content[in.ContentSHA256] {
			return errInputIdentity
		}
		c.content[in.ContentSHA256] = true
	}
	return nil
}

// row builds one anonymized record; every string it sets is a pseudonym,
// a closed-set label or a validated bot identity. noTarget reports a line
// whose target has no canonical identity.
func (c *converter) row(s inventorySite, sm *crawlreplay.SiteManifest, rec checks.CrawlLogRecord, ordinal int, seq int64) (crawlreplay.Record, bool, error) {
	row := crawlreplay.Record{T: rec.Time.Unix(), File: ordinal, Seq: seq, Site: sm.Site, Account: sm.Account, Status: rec.Status}
	switch rec.RefererClass {
	case checks.CrawlRefererMalformed:
		row.Referer = crawlreplay.RefMalformed
	case checks.CrawlRefererCrossSite:
		row.Referer = crawlreplay.RefCrossSite
	case checks.CrawlRefererSameSite:
		row.Referer = crawlreplay.RefSameSite
	}
	client, attribution := c.client(rec)
	switch attribution {
	case clientInvalid:
		sm.InvalidClient++
	case clientUnattributed:
		sm.AttributionLoss++
	default:
		if containsAddr(c.inv.infra, client) {
			row.Infra = true
			sm.Infrastructure++
		}
		if b, bound := crawlid.BindingOf(client.String()); bound {
			var err error
			if row.Binding, err = c.ps.binding(b); err != nil {
				return crawlreplay.Record{}, false, err
			}
		}
	}
	var target crawlid.Target
	hasTarget := false
	if !rec.TargetInvalid && !rec.TargetOverflow {
		if t, err := crawlid.ParseTarget(rec.Target, checks.CrawlTargetLimit); err == nil {
			target, hasTarget = t, true
			class := crawlid.Classify(rec.Method, t)
			switch {
			case class.Expensive:
				keys := crawlid.KeysFor([]byte(s.Name), class, t)
				l2, l2Err := c.ps.key(keys[1])
				l1, l1Err := c.ps.key(keys[2])
				if keyErr := errors.Join(l2Err, l1Err); keyErr != nil {
					return crawlreplay.Record{}, false, errCollision
				}
				row.Class, row.L2, row.L1 = crawlreplay.ClassExpensive, l2, l1
			case class.Dynamic:
				row.Class = crawlreplay.ClassDynamic
			}
		}
	}
	if !hasTarget {
		sm.NoTarget++
	}
	if bot := threatintel.ClaimedBotFromUA(rec.UserAgent); bot != "" && botName.MatchString(bot) {
		row.Bot = bot
		if attribution == clientOK && c.bots != nil {
			row.BotProof = c.bots.proof(bot, client, rec.Time)
		}
	}
	for _, rule := range c.labels {
		if rule.matches(s.Name, rec.Time, target, hasTarget) {
			var err error
			row.Label = rule.Label
			if row.Episode, err = c.ps.episode(rule.Episode); err != nil {
				return crawlreplay.Record{}, false, err
			}
			break
		}
	}
	return row, !hasTarget, nil
}

type clientAttribution uint8

const (
	clientOK clientAttribution = iota
	clientInvalid
	clientUnattributed
)

// client returns the address a binding comes from: the direct peer, or the
// last forwarded address a trusted proxy logged. A peer that is not a plain
// address is invalid; a trusted proxy's line without a usable forwarded
// address, or one naming another trusted proxy (an unqualified second hop),
// is unattributed.
func (c *converter) client(rec checks.CrawlLogRecord) (netip.Addr, clientAttribution) {
	peer, err := netip.ParseAddr(rec.RemoteIP)
	if err != nil || peer.Zone() != "" {
		return netip.Addr{}, clientInvalid
	}
	peer = peer.Unmap()
	if !containsAddr(c.inv.proxies, peer) {
		return peer, clientOK
	}
	if rec.XFF == "" || rec.XFFUnusable {
		return netip.Addr{}, clientUnattributed
	}
	entry := rec.XFF[strings.LastIndexByte(rec.XFF, ',')+1:]
	a, err := netip.ParseAddr(strings.TrimSpace(entry))
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, clientUnattributed
	}
	a = a.Unmap()
	if containsAddr(c.inv.proxies, a) {
		return netip.Addr{}, clientUnattributed
	}
	return a, clientOK
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

// contentReader hashes and counts the decompressed bytes of a copy.
type contentReader struct {
	r io.Reader
	h hash.Hash
	n int64
}

func (c *contentReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.h.Write(p[:n])
	c.n += int64(n)
	return n, err
}

// logReader transparently decompresses gzip copies.
func logReader(r io.Reader) (*bufio.Reader, *contentReader, error) {
	br := bufio.NewReaderSize(r, maxLine+2)
	content := &contentReader{r: br, h: sha256.New()}
	head, err := br.Peek(2)
	if err == nil && head[0] == 0x1f && head[1] == 0x8b {
		gz, gzErr := gzip.NewReader(br)
		if gzErr != nil {
			return nil, nil, gzErr
		}
		content.r = gz
	}
	return bufio.NewReaderSize(content, maxLine+2), content, nil
}

// logLine is one line as read. Size counts every byte of it, terminator
// included. Text, without LF or CRLF, is nil for an oversized line, which
// is skipped to its end without being buffered. A line is complete only
// when an LF ends it.
type logLine struct {
	text      []byte
	size      int64
	oversized bool
	complete  bool
}

// eachLine calls fn for every line, including an unterminated last one.
func eachLine(r *bufio.Reader, fn func(logLine) error) error {
	for {
		chunk, err := r.ReadSlice('\n')
		l := logLine{size: int64(len(chunk))}
		for errors.Is(err, bufio.ErrBufferFull) {
			l.oversized = true
			chunk, err = r.ReadSlice('\n')
			l.size += int64(len(chunk))
		}
		if l.size == 0 && errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return errInput
		}
		l.complete = err == nil
		if l.complete && !l.oversized {
			text := bytes.TrimSuffix(chunk[:len(chunk)-1], []byte("\r"))
			if l.oversized = len(text) > maxLine; !l.oversized {
				l.text = text
			}
		}
		if fnErr := fn(l); fnErr != nil {
			return fnErr
		}
		if !l.complete {
			return nil
		}
	}
}
