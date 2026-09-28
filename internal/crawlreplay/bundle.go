package crawlreplay

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
)

// ManifestVersion is the bundle manifest format. Version 1 called an
// observed first-to-last extent coverage; it is refused.
const ManifestVersion = 2

// Categories of lines no minute holds, as the manifest and proofs name them.
// LossNoTarget is timed: its lines are records whose volume row counts them.
const (
	LossOversized   = "oversized"
	LossRejected    = "rejected"
	LossTimeInvalid = "time_invalid"
	LossTimeFuture  = "time_future"
	LossIncomplete  = "incomplete"
	LossNoTarget    = "no_target"
)

var (
	// ErrManifest reports a manifest that is not canonical or breaks the
	// format. Messages name the field, never the value.
	ErrManifest = errors.New("crawlreplay: invalid manifest")
	// ErrBundle reports bundle files or rows that do not match their manifest.
	ErrBundle = errors.New("crawlreplay: bundle does not match its manifest")
	// ErrStrictJSON reports a document outside its closed JSON form. It
	// carries no input bytes.
	ErrStrictJSON = errors.New("crawlreplay: JSON is not in its closed form")

	accountPseudonymRe = regexp.MustCompile(`^acct-[0-9a-f]{6}$`)
	sha256Hex          = regexp.MustCompile(`^[0-9a-f]{64}$`)
	saltPrint          = regexp.MustCompile(`^[0-9a-f]{12}$`)
	revisionHex        = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
)

// ToolRevision is the source revision a bundle tool was built from.
type ToolRevision struct {
	Revision  string `json:"revision"`
	Dirty     bool   `json:"dirty"`
	GoVersion string `json:"go_version"`
}

// Clean reports a known, unmodified source revision.
func (t ToolRevision) Clean() bool { return !t.Dirty && revisionHex.MatchString(t.Revision) }

// Digest identifies a file by content, never by path.
type Digest struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

func (d Digest) valid() bool { return sha256Hex.MatchString(d.SHA256) && d.Bytes >= 0 }

// BotEvidenceRef identifies the verified-bot evidence a bundle used and the
// verified-bot list revision and configuration it came from.
type BotEvidenceRef struct {
	Digest
	D2Revision   string `json:"d2_revision"`
	ConfigSHA256 string `json:"config_sha256"`
}

// Input is one log copy: its bytes as read and its decompressed content.
// DisorderSeconds is the most any timed line's logged time trails an earlier
// timed line of the copy. A copy lists requests in completion order, so this
// is a lower bound on how late a request can be written.
type Input struct {
	Site            string `json:"site"`
	Ordinal         int    `json:"ordinal"`
	SHA256          string `json:"sha256"`
	Bytes           int64  `json:"bytes"`
	ContentSHA256   string `json:"content_sha256"`
	ContentBytes    int64  `json:"content_bytes"`
	Extent          *Span  `json:"extent,omitempty"`
	DisorderSeconds int64  `json:"disorder_seconds"`
}

// Output is one bundle file with its row count.
type Output struct {
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Rows   int64  `json:"rows"`
}

// UntimedLoss counts lines of one input and category that carry no usable
// time, between the timed lines logged before and after them (Unix seconds,
// 0 at an end of the input). Logs are written at request completion, so a
// lost request's time lies within those bounds widened by the lateness bound
// a coverage proof supplies.
type UntimedLoss struct {
	Input    int    `json:"input"`
	Category string `json:"category"`
	After    int64  `json:"after"`
	Before   int64  `json:"before"`
	Lines    int64  `json:"lines"`
}

// SiteManifest is what the converter observed for one site. Every line read
// is a record or exactly one refused category; record bytes are in volume
// rows and every other byte is unplaced. Extent is diagnostic only.
type SiteManifest struct {
	Site            string           `json:"site"`
	Account         string           `json:"account"`
	Extent          *Span            `json:"extent,omitempty"`
	Bytes           int64            `json:"bytes"`
	UnplacedBytes   int64            `json:"unplaced_bytes"`
	Lines           int64            `json:"lines"`
	Records         int64            `json:"records"`
	Oversized       int64            `json:"oversized"`
	Rejected        int64            `json:"rejected"`
	TimeInvalid     int64            `json:"time_invalid"`
	TimeFuture      int64            `json:"time_future"`
	OutOfPeriod     int64            `json:"out_of_period"`
	Incomplete      int64            `json:"incomplete"`
	NoTarget        int64            `json:"no_target"`
	AttributionLoss int64            `json:"attribution_loss"`
	InvalidClient   int64            `json:"invalid_client"`
	Infrastructure  int64            `json:"infrastructure"`
	Labels          map[string]int64 `json:"labels"`
	Untimed         []UntimedLoss    `json:"untimed"`
}

// Manifest describes one bundle: provenance, the recording period (inclusive
// Unix minutes), every input and output by digest, and per-site counts.
type Manifest struct {
	FormatVersion   int             `json:"format_version"`
	StreamVersion   int             `json:"stream_version"`
	IdentityVersion int             `json:"identity_version"`
	Tool            ToolRevision    `json:"tool"`
	SaltFingerprint string          `json:"salt_fingerprint"`
	Period          Span            `json:"period"`
	Inventory       Digest          `json:"inventory"`
	Labels          *Digest         `json:"labels,omitempty"`
	BotEvidence     *BotEvidenceRef `json:"bot_evidence,omitempty"`
	Inputs          []Input         `json:"inputs"`
	Outputs         []Output        `json:"outputs"`
	Sites           []SiteManifest  `json:"sites"`

	digest string
}

// Digest returns the SHA-256 of the manifest bytes DecodeManifest read, the
// value a coverage proof binds to; it is empty for a manifest built in memory.
func (m Manifest) Digest() string { return m.digest }

func manifestError(field string) error { return fmt.Errorf("%w: %s", ErrManifest, field) }

// EncodeManifest validates m and returns its only accepted encoding.
func EncodeManifest(m Manifest) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, manifestError("encoding")
	}
	return append(b, '\n'), nil
}

// DecodeManifest accepts only the exact bytes EncodeManifest produces, so
// unknown, duplicate, differently spelled, null or missing fields, trailing
// data and hand reformatting are all refused.
func DecodeManifest(raw []byte) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, manifestError("syntax")
	}
	canonical, err := EncodeManifest(m)
	if err != nil {
		return Manifest{}, err
	}
	if !bytes.Equal(canonical, raw) {
		return Manifest{}, manifestError("not canonical")
	}
	sum := sha256.Sum256(raw)
	m.digest = hex.EncodeToString(sum[:])
	return m, nil
}

// Validate checks the manifest against the closed format and its internal
// totals; it does not read the bundle's rows.
func (m Manifest) Validate() error {
	switch {
	case m.FormatVersion != ManifestVersion:
		return manifestError("format_version")
	case m.StreamVersion != StreamVersion:
		return manifestError("stream_version")
	case m.IdentityVersion < 1:
		return manifestError("identity_version")
	case !m.Tool.Clean():
		return manifestError("tool")
	case !saltPrint.MatchString(m.SaltFingerprint):
		return manifestError("salt_fingerprint")
	case m.Period.From <= 0 || m.Period.To < m.Period.From:
		return manifestError("period")
	case !m.Inventory.valid() || m.Inventory.Bytes == 0:
		return manifestError("inventory")
	case m.Labels != nil && (!m.Labels.valid() || m.Labels.Bytes == 0):
		return manifestError("labels")
	case m.BotEvidence != nil && (!m.BotEvidence.valid() || m.BotEvidence.Bytes == 0 ||
		!revisionHex.MatchString(m.BotEvidence.D2Revision) || !sha256Hex.MatchString(m.BotEvidence.ConfigSHA256)):
		return manifestError("bot_evidence")
	case len(m.Sites) == 0:
		return manifestError("sites")
	}
	kinds := map[string]bool{}
	for _, o := range m.Outputs {
		if (o.Kind != "records" && o.Kind != "volume") || kinds[o.Kind] || !sha256Hex.MatchString(o.SHA256) || o.Bytes < 0 || o.Rows < 0 {
			return manifestError("outputs")
		}
		kinds[o.Kind] = true
	}
	if len(kinds) != 2 {
		return manifestError("outputs")
	}
	inputs := map[string]int{}
	read := map[string]int64{}
	// Two copies with the same nonempty content would count their requests twice.
	content := map[string]bool{}
	for _, in := range m.Inputs {
		switch {
		case in.Ordinal != inputs[in.Site], !sha256Hex.MatchString(in.SHA256), in.Bytes < 0,
			!sha256Hex.MatchString(in.ContentSHA256), in.ContentBytes < 0,
			in.ContentBytes > 0 && content[in.ContentSHA256],
			in.Extent != nil && !within(*in.Extent, m.Period), in.DisorderSeconds < 0:
			return manifestError("inputs")
		}
		inputs[in.Site]++
		var ok bool
		if read[in.Site], ok = checkedSum(read[in.Site], in.ContentBytes); !ok {
			return manifestError("inputs")
		}
		if in.ContentBytes > 0 {
			content[in.ContentSHA256] = true
		}
	}
	sites := map[string]bool{}
	for i := range m.Sites {
		s := &m.Sites[i]
		if !ValidSite(s.Site) || sites[s.Site] || inputs[s.Site] == 0 {
			return manifestError("sites")
		}
		// Every decompressed byte of a site's copies is a line it counted.
		if read[s.Site] != s.Bytes {
			return manifestError("bytes")
		}
		sites[s.Site] = true
		if err := s.validate(m.Period, inputs[s.Site]); err != nil {
			return err
		}
	}
	if len(inputs) != len(sites) {
		return manifestError("inputs")
	}
	return nil
}

func (s *SiteManifest) validate(period Span, inputs int) error {
	counters := []int64{s.Bytes, s.UnplacedBytes, s.Lines, s.Records, s.Oversized, s.Rejected, s.TimeInvalid,
		s.TimeFuture, s.OutOfPeriod, s.Incomplete, s.NoTarget, s.AttributionLoss, s.InvalidClient, s.Infrastructure}
	for _, n := range counters {
		if n < 0 {
			return manifestError("counts")
		}
	}
	lines, ok := checkedSum(s.Records, s.Oversized, s.Rejected, s.TimeInvalid, s.TimeFuture, s.OutOfPeriod, s.Incomplete)
	unbound, okUnbound := checkedSum(s.AttributionLoss, s.InvalidClient)
	switch {
	case !accountPseudonymRe.MatchString(s.Account):
		return manifestError("account")
	case !ok || lines != s.Lines:
		return manifestError("lines")
	case !okUnbound || unbound > s.Records, s.NoTarget > s.Records, s.Infrastructure > s.Records:
		return manifestError("records")
	case s.UnplacedBytes > s.Bytes:
		return manifestError("unplaced_bytes")
	case s.Bytes < s.Lines, s.UnplacedBytes < s.Lines-s.Records,
		s.Lines == s.Records && s.UnplacedBytes != 0:
		return manifestError("line bytes")
	case (s.Extent == nil) != (s.Records == 0), s.Extent != nil && !within(*s.Extent, period):
		return manifestError("extent")
	case s.Labels == nil || s.Untimed == nil:
		return manifestError("site lists")
	}
	var labelled int64
	for label, n := range s.Labels {
		if (label != "" && label != LabelAttack && label != LabelHealthy && label != LabelOverload) || n < 1 {
			return manifestError("labels")
		}
		if labelled, ok = checkedSum(labelled, n); !ok {
			return manifestError("labels")
		}
	}
	if labelled != s.Records {
		return manifestError("labels")
	}
	untimed := map[string]int64{}
	for _, u := range s.Untimed {
		if _, known := untimedCategories[u.Category]; !known || u.Input < 0 || u.Input >= inputs || u.Lines < 1 || u.After < 0 || u.Before < 0 {
			return manifestError("untimed")
		}
		if untimed[u.Category], ok = checkedSum(untimed[u.Category], u.Lines); !ok {
			return manifestError("untimed")
		}
	}
	for category, counter := range map[string]int64{LossOversized: s.Oversized, LossRejected: s.Rejected,
		LossTimeInvalid: s.TimeInvalid, LossTimeFuture: s.TimeFuture, LossIncomplete: s.Incomplete} {
		if untimed[category] != counter {
			return manifestError("untimed")
		}
	}
	return nil
}

var untimedCategories = map[string]struct{}{LossOversized: {}, LossRejected: {}, LossTimeInvalid: {}, LossTimeFuture: {}, LossIncomplete: {}}

func within(s, outer Span) bool { return s.From >= outer.From && s.To <= outer.To && s.From <= s.To }

// checkedSum adds nonnegative counts, reporting overflow instead of wrapping.
func checkedSum(values ...int64) (int64, bool) {
	var total int64
	for _, v := range values {
		if v < 0 || total > math.MaxInt64-v {
			return 0, false
		}
		total += v
	}
	return total, true
}

// ReadBundleFile reads one bundle file exactly once. It hashes and counts
// every byte as it is read, decompresses a gzip file (recognized by its magic
// bytes), hands the content to fn and returns the digest of what was read,
// after checking that fn consumed the content to its end.
func ReadBundleFile(r io.Reader, fn func(io.Reader) error) (Digest, error) {
	h := sha256.New()
	counted := &countingReader{r: io.TeeReader(r, h)}
	br := bufio.NewReader(counted)
	var content io.Reader = br
	head, err := br.Peek(2)
	if err != nil && !errors.Is(err, io.EOF) {
		// bufio clears the error it reports; the next read would retry.
		return Digest{}, fmt.Errorf("%w: read", ErrBundle)
	}
	if len(head) == 2 && head[0] == 0x1f && head[1] == 0x8b {
		zr, gzErr := gzip.NewReader(br)
		if gzErr != nil {
			return Digest{}, fmt.Errorf("%w: gzip", ErrBundle)
		}
		content = zr
	}
	if err = fn(content); err != nil {
		return Digest{}, err
	}
	if n, copyErr := io.Copy(io.Discard, content); copyErr != nil || n != 0 {
		return Digest{}, fmt.Errorf("%w: unread content", ErrBundle)
	}
	if _, err = io.Copy(io.Discard, br); err != nil {
		return Digest{}, fmt.Errorf("%w: read", ErrBundle)
	}
	return Digest{SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: counted.n}, nil
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

// DecodeStrictJSON decodes exactly one JSON value into v. Member names must
// match exactly and occur once; unknown members, null values and trailing
// data are refused with ErrStrictJSON.
func DecodeStrictJSON(raw []byte, v any) error {
	dec := jsontext.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := dec.ReadToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || tok.Kind() == 'n' {
			return ErrStrictJSON
		}
	}
	if err := jsonv2.Unmarshal(raw, v, jsonv2.RejectUnknownMembers(true)); err != nil {
		return ErrStrictJSON
	}
	return nil
}
