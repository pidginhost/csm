package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/pidginhost/csm/internal/admission"
)

// legacyHourLayout is the local-time hour the legacy counter is keyed by.
const legacyHourLayout = "2006-01-02T15"

// maxLegacyHourLead bounds how far ahead of now a legacy hour may end. A
// clock stepped back leaves a later hour behind, and its count still holds
// until its own window ends; a key further ahead is damage, which would
// otherwise hold the ceiling for as long as it claims.
const maxLegacyHourLead = 24 * time.Hour

// LegacyBlockSpend reads the legacy hourly block counter for the admission
// ledger's first limit (spec 5.4 migration). The whole state file must
// validate: a damaged or unreadable file is an error, never zero spend. No
// file means no legacy blocks. The count is dated at the end of its hour in
// now's zone, the later instance of an hour the clocks repeat, and an hour
// whose window ended by now counts nothing.
func LegacyBlockSpend(statePath string, now time.Time) (admission.LegacySpend, error) {
	path := filepath.Join(statePath, blockStateFile)
	data, err := osFS.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return admission.LegacySpend{}, nil
	}
	if err != nil {
		return admission.LegacySpend{}, fmt.Errorf("reading %s: %w", path, err)
	}
	if err = validateLegacyJSON(data); err != nil {
		return admission.LegacySpend{}, fmt.Errorf("reading %s: %w", path, err)
	}
	var state blockState
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&state); err != nil {
		return admission.LegacySpend{}, fmt.Errorf("reading %s: %w", path, err)
	}
	if _, err = dec.Token(); err != io.EOF {
		return admission.LegacySpend{}, fmt.Errorf("reading %s: data after the state", path)
	}
	if err = validateLegacyState(state, now.Location()); err != nil {
		return admission.LegacySpend{}, fmt.Errorf("reading %s: %w", path, err)
	}
	end, _ := legacyHourEnd(state.HourKey, now.Location())
	switch {
	case end.After(now.Add(maxLegacyHourLead)):
		return admission.LegacySpend{}, fmt.Errorf("reading %s: hour %s ends more than a day ahead", path, state.HourKey)
	case !end.Add(admission.CeilingWindow).After(now):
		return admission.LegacySpend{}, nil
	}
	if state.BlocksThisHour == 0 {
		return admission.LegacySpend{}, nil
	}
	return admission.LegacySpend{Units: uint32(min(state.BlocksThisHour, math.MaxUint32)), At: end}, nil // #nosec G115 -- bounded by the min.
}

func validateLegacyState(s blockState, loc *time.Location) error {
	switch {
	case s.BlocksThisHour < 0:
		return errors.New("negative hourly count")
	case s.BlocksThisHour > 0 && s.HourKey == "":
		return errors.New("hourly count without its hour")
	}
	for _, key := range []string{s.HourKey, s.RateLimitWarnedHour, s.PendingDropWarnedHour} {
		if _, ok := legacyHourEnd(key, loc); key != "" && !ok {
			return fmt.Errorf("malformed hour %q", key)
		}
	}
	addrs := make([]string, 0, len(s.IPs)+len(s.Pending)+len(s.CleanupPending))
	for _, b := range s.IPs {
		addrs = append(addrs, b.IP)
	}
	for _, p := range s.Pending {
		addrs = append(addrs, p.IP)
	}
	addrs = append(addrs, s.CleanupPending...)
	for _, a := range addrs {
		if _, err := netip.ParseAddr(a); err != nil {
			return fmt.Errorf("malformed address %q", a)
		}
	}
	return nil
}

// legacyHourEnd is the end of the local hour key names in loc. An hour the
// clocks repeat ends with its later instance.
func legacyHourEnd(key string, loc *time.Location) (time.Time, bool) {
	start, err := time.ParseInLocation(legacyHourLayout, key, loc)
	if err != nil {
		return time.Time{}, false
	}
	if start.Format(legacyHourLayout) != key {
		// A fractional-hour forward step can remove the hour's start
		// while leaving its later minutes present.
		start = start.Add(time.Hour)
		if start.Format(legacyHourLayout) != key {
			return time.Time{}, false
		}
	}
	end := start.Add(time.Hour - time.Duration(start.Minute())*time.Minute - time.Duration(start.Second())*time.Second - time.Duration(start.Nanosecond()))
	for end.Format(legacyHourLayout) == key {
		end = end.Add(time.Minute)
	}
	return end, true
}

// The typed JSON decoder accepts null scalars and repeated keys. Neither
// can prove an hourly count; validate the shape before using zero values.
func validateLegacyJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := uniqueLegacyValue(dec); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&fields); err != nil {
		return err
	}
	for _, key := range []string{"blocks_this_hour", "hour_key"} {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("missing legacy field %s", key)
		}
	}
	return nil
}

func uniqueLegacyValue(dec *json.Decoder) error {
	tok, tokenErr := dec.Token()
	if tokenErr != nil {
		return tokenErr
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			key, keyErr := dec.Token()
			if keyErr != nil {
				return keyErr
			}
			name := legacyJSONFieldName(key.(string))
			if seen[name] {
				return errors.New("repeated legacy field")
			}
			seen[name] = true
			if valueErr := uniqueLegacyValue(dec); valueErr != nil {
				return valueErr
			}
		}
	case '[':
		for dec.More() {
			if valueErr := uniqueLegacyValue(dec); valueErr != nil {
				return valueErr
			}
		}
	}
	_, closeErr := dec.Token()
	return closeErr
}

// Match the typed JSON decoder's case folding when comparing field names.
func legacyJSONFieldName(key string) string {
	return strings.Map(func(r rune) rune {
		folded := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < folded {
				folded = next
			}
		}
		return folded
	}, key)
}
