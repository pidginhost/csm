package crawlreplay

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"
)

// StreamVersion is the record and volume stream format version. Version 2
// replaced version 1's range flag with verified-bot proof classes.
const StreamVersion = 2

// Request classes, mirroring crawlid.Classify.
const (
	ClassOther uint8 = iota
	ClassDynamic
	ClassExpensive
)

// Referer classes, mirroring the domlog record parser.
const (
	RefNone uint8 = iota
	RefMalformed
	RefCrossSite
	RefSameSite
)

// Verified-bot proof classes of a claimed bot identity, from historical
// evidence of the verified-bot list for that identity at the logged time. A
// claim without one stays unverified.
const (
	BotProofRange    = "range"
	BotProofDNS      = "dns"
	BotProofNegative = "negative"
)

// Labels an operator assigns before anonymization.
const (
	LabelAttack   = "attack"
	LabelHealthy  = "healthy"
	LabelOverload = "overload"
)

var (
	// ErrRecord reports a stream row that breaks the format. Messages name
	// the field, never the value, so a refusal cannot echo private input.
	ErrRecord = errors.New("crawlreplay: invalid row")
	// ErrDecode reports bytes that are not a stream row.
	ErrDecode = errors.New("crawlreplay: undecodable row")

	sitePseudonym    = regexp.MustCompile(`^dom-[0-9a-f]{6}\.example$`)
	accountPseudonym = regexp.MustCompile(`^acct-[0-9a-f]{6}$`)
	bindingPseudonym = regexp.MustCompile(`^b-[0-9a-f]{16}$`)
	keyPseudonym     = regexp.MustCompile(`^k-[0-9a-f]{16}$`)
	botIdentity      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	episodeID        = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
)

// Record is one logged request with every identity replaced by a salted
// pseudonym. Keys and bindings keep equality, L1 and L2 keep the hierarchy
// (both belong to the record's site), and no target, query value, address,
// user agent or Referer survives. File and Seq keep the logged order.
type Record struct {
	T        int64  `json:"t"`
	File     int    `json:"f"`
	Seq      int64  `json:"n"`
	Site     string `json:"site"`
	Account  string `json:"acct,omitempty"`
	Binding  string `json:"b,omitempty"`
	L2       string `json:"l2,omitempty"`
	L1       string `json:"l1,omitempty"`
	Class    uint8  `json:"c"`
	Status   int    `json:"s"`
	Referer  uint8  `json:"r"`
	Bot      string `json:"bot,omitempty"`
	BotProof string `json:"bot_proof,omitempty"`
	Infra    bool   `json:"infra,omitempty"`
	Label    string `json:"label,omitempty"`
	Episode  string `json:"ep,omitempty"`
}

// Validate checks every field against the closed stream format.
func (r Record) Validate() error {
	switch {
	case r.T <= 0:
		return fieldError("t")
	case r.File < 0:
		return fieldError("f")
	case r.Seq < 1:
		return fieldError("n")
	case !sitePseudonym.MatchString(r.Site):
		return fieldError("site")
	case r.Account != "" && !accountPseudonym.MatchString(r.Account):
		return fieldError("acct")
	case r.Binding != "" && !bindingPseudonym.MatchString(r.Binding):
		return fieldError("b")
	case r.Class > ClassExpensive:
		return fieldError("c")
	case (r.Class == ClassExpensive) != (r.L2 != ""),
		r.L2 != "" && !keyPseudonym.MatchString(r.L2):
		return fieldError("l2")
	case (r.Class == ClassExpensive) != (r.L1 != ""),
		r.L1 != "" && !keyPseudonym.MatchString(r.L1):
		return fieldError("l1")
	case r.Status < 100 || r.Status > 599:
		return fieldError("s")
	case r.Referer > RefSameSite:
		return fieldError("r")
	case r.Bot != "" && !botIdentity.MatchString(r.Bot):
		return fieldError("bot")
	case r.BotProof != "" && (r.Bot == "" || r.Binding == "" || (r.BotProof != BotProofRange && r.BotProof != BotProofDNS && r.BotProof != BotProofNegative)):
		return fieldError("bot_proof")
	}
	episodic := r.Label == LabelAttack || r.Label == LabelOverload
	switch {
	case r.Label != "" && !episodic && r.Label != LabelHealthy:
		return fieldError("label")
	case episodic != (r.Episode != ""),
		r.Episode != "" && !episodeID.MatchString(r.Episode):
		return fieldError("ep")
	}
	return nil
}

// Volume counts one site's logged lines in one UTC minute, including lines
// that yielded no target or no client binding, for read-budget and coverage
// calibration. Lines the parser refused or that carry no valid time cannot
// be placed in a minute; the converter's manifest counts those.
type Volume struct {
	Site      string `json:"site"`
	Minute    int64  `json:"m"`
	Lines     int64  `json:"lines"`
	Bytes     int64  `json:"bytes"`
	NoTarget  int64  `json:"no_target"`
	NoBinding int64  `json:"no_binding"`
}

// Validate checks every field against the closed stream format.
func (v Volume) Validate() error {
	switch {
	case !sitePseudonym.MatchString(v.Site):
		return fieldError("site")
	case v.Minute <= 0:
		return fieldError("m")
	case v.Lines < 1:
		return fieldError("lines")
	case v.Bytes < v.Lines:
		return fieldError("bytes")
	case v.NoTarget < 0 || v.NoTarget > v.Lines:
		return fieldError("no_target")
	case v.NoBinding < 0 || v.NoBinding > v.Lines:
		return fieldError("no_binding")
	}
	return nil
}

func fieldError(name string) error { return fmt.Errorf("%w: %s", ErrRecord, name) }

// ValidSite reports whether name is a site pseudonym of the closed format,
// so a bundle's other files can be held to the rule its rows follow.
func ValidSite(name string) bool { return sitePseudonym.MatchString(name) }

type row interface{ Validate() error }

// ReadRecords decodes a JSON record stream and calls fn for each record in
// stream order. Fields must use their exact JSON names, occur at most once,
// and be non-null. Fields without omitempty are required, even when zero.
// Invalid rows stop the read without calling fn for that row.
func ReadRecords(r io.Reader, fn func(Record) error) error { return readRows(r, fn) }

// ReadVolume decodes a JSON volume stream under the same field rules as
// ReadRecords and calls fn for each valid row.
func ReadVolume(r io.Reader, fn func(Volume) error) error { return readRows(r, fn) }

func readRows[T row](r io.Reader, fn func(T) error) error {
	// Derive required and optional names from the writer's schema so the
	// reader cannot silently invent zero-valued fields or accept aliases.
	fields := make(map[string]bool)
	typ := reflect.TypeFor[T]()
	for i := range typ.NumField() {
		name, option, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		fields[name] = option != "omitempty"
	}
	dec := json.NewDecoder(bufio.NewReader(r))
	for n := 1; ; n++ {
		var data json.RawMessage
		if err := dec.Decode(&data); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("row %d: %w", n, ErrDecode)
		}
		var v T
		if err := decodeRow(data, &v, fields); err != nil {
			return fmt.Errorf("row %d: %w", n, ErrDecode)
		}
		if err := v.Validate(); err != nil {
			return fmt.Errorf("row %d: %w", n, err)
		}
		if err := fn(v); err != nil {
			return err
		}
	}
}

func decodeRow(data []byte, v any, fields map[string]bool) error {
	// Unmarshal alone accepts case-insensitive names, repeated keys and
	// null scalars. Check the object before those distinctions are lost.
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return ErrDecode
	}
	seen := make(map[string]bool, len(fields))
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return ErrDecode
		}
		name, _ := tok.(string)
		if _, ok := fields[name]; !ok || seen[name] {
			return ErrDecode
		}
		seen[name] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil || string(value) == "null" {
			return ErrDecode
		}
	}
	if _, err := dec.Token(); err != nil {
		return ErrDecode
	}
	for name, required := range fields {
		if required && !seen[name] {
			return ErrDecode
		}
	}
	return json.Unmarshal(data, v)
}

// WriteRow validates v and writes it as one JSON line.
func WriteRow[T row](w io.Writer, v T) error {
	if err := v.Validate(); err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	n, err := w.Write(b)
	if err == nil && n < len(b) {
		return io.ErrShortWrite
	}
	return err
}
