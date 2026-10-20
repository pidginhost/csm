package learn

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// Result is one digest's reply from the inspection plugin. Stored is the
// full stored digest a hit matched; it is empty for a miss.
type Result struct {
	Queried, Stored  Digest
	Found, Confirmed bool
	Prob             float64
	Value            int64
	Flag             int
}

// Inspection is a complete, validated inspection: one result per distinct
// queried digest.
type Inspection struct {
	Results  []Result
	Distinct int
}

// ErrMessageRejected identifies a body the plugin could not process. It
// still invalidates the inspection, but says nothing about backend health.
var ErrMessageRejected = errors.New("inspection rejected the message")

// rawResult keeps every field optional so absence is detectable.
type rawResult struct {
	Queried   *string         `json:"queried"`
	Found     *bool           `json:"found"`
	Digest    *string         `json:"digest"`
	Prob      json.RawMessage `json:"prob"`
	Value     json.RawMessage `json:"value"`
	Flag      json.RawMessage `json:"flag"`
	Confirmed *bool           `json:"confirmed"`
}

// ParseInspection validates a plugin reply (spec 7.4). explicit is the
// digest list of an exact-only check, nil for a body inspection. Anything
// missing, unexpected, duplicate, malformed or failed invalidates the whole
// inspection; it never reads as a miss. Errors are fixed text.
func ParseInspection(body []byte, explicit []Digest) (Inspection, error) {
	fields, err := objectFields(body, "results", "errors", "complete", "distinct")
	if err != nil || len(fields) != 4 {
		return Inspection{}, errors.New("inspection reply is malformed")
	}
	var complete bool
	var distinct int
	if json.Unmarshal(fields["complete"], &complete) != nil || !complete {
		if bytes.Equal(fields["complete"], []byte("false")) && explicit == nil && rejectedMessage(fields) {
			return Inspection{}, ErrMessageRejected
		}
		return Inspection{}, errors.New("inspection is incomplete")
	}
	if json.Unmarshal(fields["distinct"], &distinct) != nil || distinct < 0 || distinct > MaxExplicitDigests {
		return Inspection{}, errors.New("inspection has an invalid digest count")
	}
	var problems []json.RawMessage
	if err := uclList(fields["errors"], &problems); err != nil || len(problems) != 0 {
		return Inspection{}, errors.New("inspection reported errors")
	}
	var raws []json.RawMessage
	if err := uclList(fields["results"], &raws); err != nil {
		return Inspection{}, errors.New("inspection results are not a list")
	}
	var want map[Digest]bool
	if explicit != nil {
		want = map[Digest]bool{}
		for _, d := range explicit {
			if _, err := ParseDigest(string(d)); err != nil {
				return Inspection{}, errors.New("inspection request holds an invalid digest")
			}
			want[d] = true
		}
		if distinct != len(want) {
			return Inspection{}, errors.New("inspection answered a different digest count")
		}
	}
	if len(raws) != distinct {
		return Inspection{}, errors.New("inspection results do not match its digest count")
	}
	insp := Inspection{Results: make([]Result, 0, len(raws)), Distinct: distinct}
	seen := map[Digest]bool{}
	for _, raw := range raws {
		r, err := parseResult(raw)
		if err != nil {
			return Inspection{}, err
		}
		if seen[r.Queried] {
			return Inspection{}, errors.New("inspection answered a digest twice")
		}
		seen[r.Queried] = true
		if want != nil && (!want[r.Queried] || r.Found && r.Stored != r.Queried) {
			return Inspection{}, errors.New("exact inspection returned an unrequested digest")
		}
		insp.Results = append(insp.Results, r)
	}
	return insp, nil
}

// Only the plugin's pre-query body failures are local to one report.
// Exact checks, storage errors and malformed replies still stop submissions.
func rejectedMessage(fields map[string]json.RawMessage) bool {
	var problems, results []json.RawMessage
	var distinct int
	if uclList(fields["errors"], &problems) != nil || len(problems) != 1 ||
		uclList(fields["results"], &results) != nil || len(results) != 0 ||
		json.Unmarshal(fields["distinct"], &distinct) != nil {
		return false
	}
	var reason string
	if json.Unmarshal(problems[0], &reason) != nil {
		return false
	}
	switch reason {
	case "cannot process message", "cannot hash message":
		return distinct == 0
	case "too many digests":
		return distinct > MaxExplicitDigests
	default:
		return false
	}
}

func parseResult(raw json.RawMessage) (Result, error) {
	fields, err := objectFields(raw, "queried", "found", "digest", "prob", "value", "flag", "confirmed")
	if err != nil {
		return Result{}, err
	}
	var rr rawResult
	if err = json.Unmarshal(raw, &rr); err != nil || rr.Queried == nil || rr.Found == nil || rr.Prob == nil || rr.Value == nil || rr.Flag == nil || rr.Confirmed == nil {
		return Result{}, errors.New("inspection result is malformed")
	}
	q, err := ParseDigest(*rr.Queried)
	if err != nil {
		return Result{}, errors.New("inspection result has an invalid digest")
	}
	value, okValue := wholeNumber(rr.Value)
	flag, okFlag := wholeNumber(rr.Flag)
	prob, okProb := inspectionNumber(rr.Prob)
	if !okValue || !okFlag || !okProb || prob.Sign() < 0 || prob.Cmp(big.NewRat(1, 1)) > 0 || value < 0 {
		return Result{}, errors.New("inspection result has invalid values")
	}
	p, _ := prob.Float64()
	r := Result{Queried: q, Found: *rr.Found, Prob: p, Value: value}
	if !r.Found {
		if value != 0 || prob.Sign() != 0 || flag != 0 || *rr.Confirmed || fields["digest"] != nil {
			return Result{}, errors.New("inspection miss carries a value")
		}
		return r, nil
	}
	if rr.Digest == nil || !*rr.Confirmed || flag != 1 {
		return Result{}, errors.New("inspection hit is not a confirmed CSM digest")
	}
	if r.Stored, err = ParseDigest(*rr.Digest); err != nil {
		return Result{}, errors.New("inspection hit has an invalid stored digest")
	}
	r.Confirmed, r.Flag = true, 1
	return r, nil
}

// wholeNumber reads a nonfractional JSON number; Lua numbers may arrive as
// 2 or 2.0.
func wholeNumber(raw json.RawMessage) (int64, bool) {
	n, ok := inspectionNumber(raw)
	if !ok || !n.IsInt() || !n.Num().IsInt64() {
		return 0, false
	}
	return n.Num().Int64(), true
}

// Validate the decimal value before rounding it to float64; rounding can
// turn a fractional value into an integer or a nonzero miss into zero.
func inspectionNumber(raw json.RawMessage) (*big.Rat, bool) {
	if len(raw) == 0 || (raw[0] != '-' && (raw[0] < '0' || raw[0] > '9')) {
		return nil, false
	}
	return new(big.Rat).SetString(string(raw))
}

// uclList decodes a list, reading rspamd's {} encoding of an empty Lua table
// as an empty list.
func uclList(raw json.RawMessage, out *[]json.RawMessage) error {
	if fields, err := objectFields(raw); err == nil && len(fields) == 0 {
		*out = nil
		return nil
	}
	if len(raw) == 0 || raw[0] != '[' {
		return errors.New("not a list")
	}
	return json.Unmarshal(raw, out)
}

// objectFields reads one JSON object allowing only the named fields, with
// no duplicates, null values or trailing data. Callers check required fields.
func objectFields(data []byte, names ...string) (map[string]json.RawMessage, error) {
	malformed := errors.New("inspection reply is malformed")
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, malformed
	}
	allowed := map[string]bool{}
	for _, n := range names {
		allowed[n] = true
	}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		key, ok := tok.(string)
		if err != nil || !ok || !allowed[key] || fields[key] != nil {
			return nil, malformed
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil || bytes.Equal(v, []byte("null")) {
			return nil, malformed
		}
		fields[key] = v
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, malformed
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, malformed
	}
	return fields, nil
}

// ExactValue reads d's stored value from an exact-only inspection. A miss is
// value 0, not present; a hit on another stored digest is an error.
func (i Inspection) ExactValue(d Digest) (value int64, present bool, err error) {
	for _, r := range i.Results {
		if r.Queried != d {
			continue
		}
		if !r.Found {
			return 0, false, nil
		}
		if r.Stored != d {
			return 0, false, fmt.Errorf("digest matched another stored digest")
		}
		return r.Value, true, nil
	}
	return 0, false, errors.New("digest was not inspected")
}
