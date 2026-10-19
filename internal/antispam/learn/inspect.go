package learn

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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

// rawResult keeps every field optional so absence is detectable.
type rawResult struct {
	Queried   *string      `json:"queried"`
	Found     *bool        `json:"found"`
	Digest    *string      `json:"digest"`
	Prob      *float64     `json:"prob"`
	Value     *json.Number `json:"value"`
	Flag      *json.Number `json:"flag"`
	Confirmed *bool        `json:"confirmed"`
}

// ParseInspection validates a plugin reply (spec 7.4). explicit is the
// digest list of an exact-only check, nil for a body inspection. Anything
// missing, unexpected, duplicate, malformed or failed invalidates the whole
// inspection; it never reads as a miss. Errors are fixed text.
func ParseInspection(body []byte, explicit []Digest) (Inspection, error) {
	fields, err := objectFields(body, "results", "errors", "complete", "distinct")
	if err != nil {
		return Inspection{}, err
	}
	var complete bool
	var distinct int
	if json.Unmarshal(fields["complete"], &complete) != nil || !complete {
		return Inspection{}, errors.New("inspection is incomplete")
	}
	if json.Unmarshal(fields["distinct"], &distinct) != nil || distinct < 0 {
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

func parseResult(raw json.RawMessage) (Result, error) {
	var rr rawResult
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rr); err != nil || rr.Queried == nil || rr.Found == nil || rr.Prob == nil || rr.Value == nil || rr.Flag == nil {
		return Result{}, errors.New("inspection result is malformed")
	}
	q, err := ParseDigest(*rr.Queried)
	if err != nil {
		return Result{}, errors.New("inspection result has an invalid digest")
	}
	value, okValue := wholeNumber(*rr.Value)
	flag, okFlag := wholeNumber(*rr.Flag)
	prob := *rr.Prob
	if !okValue || !okFlag || math.IsNaN(prob) || prob < 0 || prob > 1 || value < 0 {
		return Result{}, errors.New("inspection result has invalid values")
	}
	r := Result{Queried: q, Found: *rr.Found, Prob: prob, Value: value, Flag: int(flag)}
	if !r.Found {
		if value != 0 || prob != 0 || flag != 0 {
			return Result{}, errors.New("inspection miss carries a value")
		}
		return r, nil
	}
	if rr.Digest == nil || rr.Confirmed == nil || !*rr.Confirmed || flag != 1 {
		return Result{}, errors.New("inspection hit is not a confirmed CSM digest")
	}
	if r.Stored, err = ParseDigest(*rr.Digest); err != nil {
		return Result{}, errors.New("inspection hit has an invalid stored digest")
	}
	r.Confirmed = true
	return r, nil
}

// wholeNumber reads a nonfractional JSON number; Lua numbers may arrive as
// 2 or 2.0.
func wholeNumber(n json.Number) (int64, bool) {
	if i, err := n.Int64(); err == nil {
		return i, true
	}
	f, err := n.Float64()
	if err != nil || f != math.Trunc(f) || math.Abs(f) > 1<<53 {
		return 0, false
	}
	return int64(f), true
}

// uclList decodes a list, reading rspamd's {} encoding of an empty Lua table
// as an empty list.
func uclList(raw json.RawMessage, out *[]json.RawMessage) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("{}")) {
		*out = nil
		return nil
	}
	if len(raw) == 0 || raw[0] != '[' {
		return errors.New("not a list")
	}
	return json.Unmarshal(raw, out)
}

// objectFields reads one JSON object holding exactly the named fields, with
// no duplicates and nothing after it.
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
		if err := dec.Decode(&v); err != nil {
			return nil, malformed
		}
		fields[key] = v
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, malformed
	}
	if _, err := dec.Token(); err != io.EOF || len(fields) != len(names) {
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
