package responsereplay

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Finding is one recorded finding, reduced to what replay reads. There is no
// source address field: the audit schema has none, and replay extracts it
// from the message exactly as the live path does.
type Finding struct {
	At        time.Time
	Check     string
	Severity  string
	Message   string
	Details   string
	FindingID string
	// Ordinal is the 1-based row of the finding in its recording.
	Ordinal int
}

// Batch is the findings recorded at one instant. It is inferred from equal
// timestamps: a recording holds no scan or dispatch boundaries, and it holds
// no empty scans at all.
type Batch struct {
	At       time.Time
	Findings []Finding
}

// Recording is a read finding stream and its provenance.
type Recording struct {
	Findings []Finding
	// SHA256 covers the exact bytes read from disk, compressed or not.
	SHA256 string
	Rows   int
	// Unstamped counts rows with a zero timestamp. They have no replay
	// position, so they are counted and left out.
	Unstamped int
}

// replayError is a fixed refusal code; it never carries input bytes.
type replayError string

func (e replayError) Error() string { return string(e) }

const (
	errOpen           replayError = "cannot open"
	errRead           replayError = "read failed"
	errGzip           replayError = "not a complete gzip stream"
	errVersion        replayError = "unsupported version"
	errMissingVersion replayError = "missing version"
	errMissingTime    replayError = "missing timestamp"
	errNotObject      replayError = "not one JSON object"
	errSyntax         replayError = "malformed JSON"
	errUnknownField   replayError = "unclassified field"
	errDuplicateKey   replayError = "repeated field"
	errNull           replayError = "null value"
	errTrailing       replayError = "data after the object"
	errType           replayError = "field has the wrong type"
	errLineTooLong    replayError = "line over the limit"
	errTooLong        replayError = "field over its length limit"
	errTooMany        replayError = "array over its element limit"
	errTooDeep        replayError = "nesting over the parent limit"
)

// readError places a code by line. Line 0 is the file as a whole.
type readError struct {
	line int
	code error
}

func (e readError) Error() string {
	if e.line == 0 {
		return fmt.Sprintf("recording: %v", e.code)
	}
	return fmt.Sprintf("recording line %d: %v", e.line, e.code)
}

func (e readError) Unwrap() error { return e.code }

// The same offline parser limits the recording tool applies.
const (
	maxLineBytes   = 16 << 20
	maxTextBytes   = 64 << 10
	maxScalarBytes = 4 << 10
	maxArrayItems  = 1024
	maxParentDepth = 32
)

const auditSchemaVersion = 1

// wireEvent mirrors the audit log's finding schema field for field; the
// external schema test fails when the real type changes. Version and
// timestamp are pointers so an absent key is told apart from a zero value.
type wireEvent struct {
	V         *int         `json:"v"`
	Timestamp *time.Time   `json:"ts"`
	FindingID string       `json:"finding_id"`
	Severity  string       `json:"severity"`
	Check     string       `json:"check"`
	Message   string       `json:"message"`
	Details   string       `json:"details,omitempty"`
	FilePath  string       `json:"file_path,omitempty"`
	Hostname  string       `json:"hostname"`
	TenantID  string       `json:"tenant_id,omitempty"`
	Domain    string       `json:"domain,omitempty"`
	Mailbox   string       `json:"mailbox,omitempty"`
	Process   *wireProcess `json:"process,omitempty"`
}

type wireProcess struct {
	PID       int          `json:"pid"`
	PPID      int          `json:"ppid"`
	UID       int          `json:"uid"`
	User      string       `json:"user,omitempty"`
	Account   string       `json:"account,omitempty"`
	Comm      string       `json:"comm,omitempty"`
	Exe       string       `json:"exe,omitempty"`
	Cmdline   []string     `json:"cmdline,omitempty"`
	StartedAt *time.Time   `json:"started_at,omitempty"`
	Parent    *wireProcess `json:"parent,omitempty"`
}

// ReadFindings reads a plain or gzip JSONL recording to its end; reading
// through EOF is what surfaces a bad gzip checksum or trailer. Rows keep
// their recorded order.
func ReadFindings(path string) (Recording, error) {
	fail := func(line int, code error) (Recording, error) { return Recording{}, readError{line, code} }
	f, err := os.Open(path) // #nosec G304 -- operator-chosen recording
	if err != nil {
		return fail(0, errOpen)
	}
	defer f.Close()
	h := sha256.New()
	raw := io.TeeReader(f, h)
	r := raw
	compressed := strings.HasSuffix(path, ".gz")
	if compressed {
		zr, err := gzip.NewReader(raw)
		if err != nil {
			return fail(0, errGzip)
		}
		defer func() { _ = zr.Close() }()
		r = zr
	}
	var rec Recording
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), maxLineBytes+1)
	line := 0
	for sc.Scan() {
		line++
		// Only JSON whitespace separates rows; other space is part of one.
		data := bytes.Trim(sc.Bytes(), " \t\r\n")
		if len(data) == 0 {
			continue
		}
		rec.Rows++
		finding, stamped, err := decodeFinding(data)
		if err != nil {
			return fail(line, err)
		}
		if !stamped {
			rec.Unstamped++
			continue
		}
		finding.Ordinal = rec.Rows
		rec.Findings = append(rec.Findings, finding)
	}
	if err := sc.Err(); err != nil {
		switch {
		case errors.Is(err, bufio.ErrTooLong):
			return fail(line+1, errLineTooLong)
		case compressed:
			return fail(0, errGzip)
		}
		return fail(0, errRead)
	}
	rec.SHA256 = hex.EncodeToString(h.Sum(nil))
	return rec, nil
}

// decodeFinding decodes one row. stamped is false for a zero timestamp.
func decodeFinding(data []byte) (Finding, bool, error) {
	var e wireEvent
	if err := decodeStrict(data, &e); err != nil {
		return Finding{}, false, err
	}
	switch {
	case e.V == nil:
		return Finding{}, false, errMissingVersion
	case *e.V != auditSchemaVersion:
		return Finding{}, false, errVersion
	case e.Timestamp == nil:
		return Finding{}, false, errMissingTime
	}
	f := Finding{At: *e.Timestamp, Check: e.Check, Severity: e.Severity, Message: e.Message, Details: e.Details, FindingID: e.FindingID}
	return f, !e.Timestamp.IsZero(), nil
}

// Batches groups findings by instant, in time order. Equal instants keep
// their recorded order whatever offset they were written with. The input is
// not modified.
func Batches(findings []Finding) []Batch {
	sorted := append([]Finding(nil), findings...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].At.Before(sorted[j].At) })
	var out []Batch
	for _, f := range sorted {
		if n := len(out); n > 0 && out[n-1].At.Equal(f.At) {
			out[n-1].Findings = append(out[n-1].Findings, f)
			continue
		}
		out = append(out, Batch{At: f.At, Findings: []Finding{f}})
	}
	return out
}

// decodeStrict decodes exactly one JSON object into v. Go's decoder matches
// keys case-insensitively, keeps the last of repeated keys and stops after
// the first value, so a token pass first checks every key against the exact
// field names of v and rejects duplicates, nulls, overlong values and
// anything after the object. The recording tool applies the same rules with
// its own copy: this package may import nothing outside the standard library.
func decodeStrict(data []byte, v any) error {
	if len(data) > maxLineBytes {
		return errLineTooLong
	}
	if !validJSONUnicode(data) {
		return errSyntax
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if delim, ok := tok.(json.Delim); err != nil || !ok || delim != '{' {
		if err != nil && !errors.Is(err, io.EOF) {
			return errSyntax
		}
		return errNotObject
	}
	if err := checkObject(dec, reflect.TypeOf(v).Elem(), map[reflect.Type]int{}); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errTrailing
	}
	strict := json.NewDecoder(bytes.NewReader(data))
	strict.DisallowUnknownFields()
	if err := strict.Decode(v); err != nil {
		return errType
	}
	// More reports only whether a value follows in the current array or
	// object; a second Decode is the check that nothing follows at all.
	if err := strict.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return errTrailing
	}
	return nil
}

var timeType = reflect.TypeFor[time.Time]()

var longTextFields = map[string]bool{"message": true, "details": true, "file_path": true, "exe": true, "cmdline": true}

func checkObject(dec *json.Decoder, t reflect.Type, depth map[reflect.Type]int) error {
	if t.Kind() == reflect.Map && t.Key().Kind() == reflect.String {
		return checkMap(dec, t)
	}
	if t.Kind() != reflect.Struct || t == timeType {
		return errType
	}
	if depth[t] > maxParentDepth {
		return errTooDeep
	}
	depth[t]++
	defer func() { depth[t]-- }()
	fields := jsonFieldTypes(t)
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return errSyntax
		}
		key, _ := tok.(string)
		field, ok := fields[key]
		if !ok {
			return errUnknownField
		}
		if seen[key] {
			return errDuplicateKey
		}
		seen[key] = true
		if err := checkValue(dec, field, key, depth); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return errSyntax
	}
	return nil
}

// checkMap reads a keyed counter object such as a manifest's coverage:
// keys are bounded and unique, values are scalars of the element type.
func checkMap(dec *json.Decoder, t reflect.Type) error {
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return errSyntax
		}
		key, _ := tok.(string)
		if len(key) > maxScalarBytes {
			return errTooLong
		}
		if seen[key] {
			return errDuplicateKey
		}
		seen[key] = true
		if err := checkValue(dec, t.Elem(), key, map[reflect.Type]int{}); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return errSyntax
	}
	return nil
}

func checkValue(dec *json.Decoder, t reflect.Type, key string, depth map[reflect.Type]int) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	tok, err := dec.Token()
	if err != nil {
		return errSyntax
	}
	limit := maxScalarBytes
	if longTextFields[key] {
		limit = maxTextBytes
	}
	switch tok := tok.(type) {
	case nil:
		return errNull
	case json.Delim:
		switch tok {
		case '{':
			return checkObject(dec, t, depth)
		case '[':
			if t.Kind() != reflect.Slice {
				return errType
			}
			for n := 0; dec.More(); n++ {
				if n == maxArrayItems {
					return errTooMany
				}
				if err := checkValue(dec, t.Elem(), key, depth); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return errSyntax
			}
			return nil
		}
		return errSyntax
	case string:
		if t.Kind() != reflect.String && t != timeType {
			return errType
		}
		if len(tok) > limit {
			return errTooLong
		}
		if t == timeType {
			stamp, err := time.Parse(time.RFC3339Nano, tok)
			if err != nil {
				return errType
			}
			// Go parses offsets its JSON encoder refuses to write back.
			if _, err := stamp.MarshalJSON(); err != nil {
				return errType
			}
		}
	case json.Number:
		switch t.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Float32, reflect.Float64:
		default:
			return errType
		}
		if len(tok) > maxScalarBytes {
			return errTooLong
		}
	case bool:
		if t.Kind() != reflect.Bool {
			return errType
		}
	}
	return nil
}

// encoding/json replaces malformed UTF-8 and lone UTF-16 surrogates with
// U+FFFD. Distinct raw identifiers would then become the same join key.
// Check the original string bytes before either decoding pass loses them.
func validJSONUnicode(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	for i := 0; i < len(data); i++ {
		if data[i] != '"' {
			continue
		}
		for i++; i < len(data) && data[i] != '"'; i++ {
			if data[i] != '\\' {
				continue
			}
			i++
			if i >= len(data) {
				return false
			}
			if data[i] != 'u' {
				continue
			}
			if i+4 >= len(data) {
				return false
			}
			u, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
			if err != nil || u >= 0xdc00 && u <= 0xdfff {
				return false
			}
			i += 4
			if u < 0xd800 || u > 0xdbff {
				continue
			}
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

var fieldTypeCache sync.Map

func jsonFieldTypes(t reflect.Type) map[string]reflect.Type {
	if cached, ok := fieldTypeCache.Load(t); ok {
		return cached.(map[string]reflect.Type)
	}
	fields := map[string]reflect.Type{}
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if !f.IsExported() || name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		fields[name] = f.Type
	}
	fieldTypeCache.Store(t, fields)
	return fields
}
