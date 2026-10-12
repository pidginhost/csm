package antispam

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// DefaultMaxMessage is rspamd's built-in max_message (DEFAULT_MAX_MESSAGE in
// rspamd 3.0 and 4.2.1), in effect when configdump omits the setting.
const DefaultMaxMessage = 50 << 20

// sizeHeadroom is what Exim adds around a message before rspamd reads it:
// the mbox From line, X-Envelope-From, an X-Envelope-To listing every
// recipient, and Exim's Received header. A larger envelope makes rspamd
// refuse the scan, which fails open with a scan error.
const sizeHeadroom = 1 << 20

// EximSettingNames are the options the collector reads with one `exim -bP`.
// CheckHost needs message_size_limit and log_file_path; the collector uses
// the rest for Exim's identity and system filter.
func EximSettingNames() []string {
	return []string{"message_size_limit", "log_file_path", "exim_user", "exim_group", "system_filter"}
}

// ParseEximSize reads a non-negative Exim integer with an optional sign
// and K, M or G suffix in either case (powers of 1024).
func ParseEximSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	shift := 0
	if s != "" {
		switch s[len(s)-1] {
		case 'k', 'K':
			shift = 10
		case 'm', 'M':
			shift = 20
		case 'g', 'G':
			shift = 30
		}
	}
	if shift != 0 {
		s = s[:len(s)-1]
	}
	digits := s
	if digits != "" && (digits[0] == '+' || digits[0] == '-') {
		digits = digits[1:]
	}
	if digits == "" || strings.Trim(digits, "0123456789") != "" {
		return 0, errors.New("not a plain Exim size")
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 || n > (1<<62)>>shift {
		return 0, errors.New("size out of range")
	}
	return n << shift, nil
}

// MaxMessage reads max_message from `rspamadm configdump -j options`. Zero
// means unlimited; an absent setting is DefaultMaxMessage. Rspamd converts
// numeric values to bytes, discarding any fractional part of a float.
func MaxMessage(out []byte) (int64, error) {
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.UseNumber()
	if token, err := dec.Token(); err != nil || token != json.Delim('{') {
		return 0, errors.New("configdump options: expected an object")
	}
	// A duplicate can hide a smaller limit behind an unlimited value.
	// Decode fields separately so encoding/json cannot choose the last one.
	opts := make(map[string]any)
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return 0, errors.New("configdump options: invalid JSON")
		}
		key, _ := token.(string)
		if _, seen := opts[key]; seen {
			return 0, errors.New("configdump options: duplicate field")
		}
		var value any
		if err := dec.Decode(&value); err != nil {
			return 0, errors.New("configdump options: invalid JSON")
		}
		opts[key] = value
	}
	if token, err := dec.Token(); err != nil || token != json.Delim('}') {
		return 0, errors.New("configdump options: invalid JSON")
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return 0, errors.New("configdump options: trailing data")
	}
	raw, ok := opts["max_message"]
	if !ok {
		return DefaultMaxMessage, nil
	}
	num, ok := raw.(json.Number)
	if !ok {
		return 0, errors.New("configdump options: max_message is not a number")
	}
	n, err := num.Int64()
	if err == nil && n >= 0 {
		return n, nil
	}
	// Rspamd's UCL integer conversion also accepts floating-point values.
	// Keep plain integers exact and use the same truncation for floats.
	size, err := strconv.ParseFloat(num.String(), 64)
	if err != nil || size < 0 || size >= 1<<63 {
		return 0, errors.New("configdump options: max_message is not a byte count")
	}
	return int64(size), nil
}

// checkMessageSize applies spec section 6.2 item 10: rspamd must accept
// every message Exim accepts, with the envelope Exim adds.
func checkMessageSize(settings map[string]string, options CommandResult) []Problem {
	var out []Problem
	add := func(sev Severity, format string, args ...any) {
		out = append(out, Problem{Code: CodeMessageSize, Severity: sev, Detail: fmt.Sprintf(format, args...)})
	}
	raw, ok := settings["message_size_limit"]
	if !ok {
		add(Temporary, "exim -bP did not report message_size_limit")
		return out
	}
	limit, err := ParseEximSize(raw)
	switch {
	case err != nil:
		add(Temporary, "Exim's message_size_limit is not a plain size; CSM cannot compare it with rspamd's max_message")
		return out
	case limit == 0:
		add(Definite, "Exim's message_size_limit is unlimited; set a finite limit so rspamd can scan every accepted message")
		return out
	}
	if options.Err != nil {
		add(Temporary, "rspamadm configdump options failed; check rspamd")
		return out
	}
	maxMessage, err := MaxMessage([]byte(options.Stdout))
	switch {
	case err != nil:
		add(Temporary, "rspamadm configdump did not report a readable max_message")
	case maxMessage != 0 && maxMessage < limit+sizeHeadroom:
		add(Definite, "rspamd max_message is %d bytes, below Exim's message_size_limit of %d bytes plus %d bytes for the envelope Exim adds; raise max_message in /etc/rspamd/local.d/options.inc",
			maxMessage, limit, sizeHeadroom)
	}
	return out
}
