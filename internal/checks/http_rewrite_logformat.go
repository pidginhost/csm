package checks

import "strings"

// CSM access readers use the first space-delimited field or skip leading
// ASCII whitespace and read the first token. splitlogs strips one field
// before either reader runs. Both interpretations must be safe. The
// ModSecurity reader takes its client from the error-log prefix. A format
// that writes request data at either read position logs a chosen address.

// apacheLogItem is one placeholder of an Apache log format: its handler
// ("h", "i", "^ti") and its {argument}.
type apacheLogItem struct {
	handler  string
	arg      string
	required bool
	level    int
}

// apacheLogItemAt parses the placeholder whose '%' is at format[i], as
// mod_log_config does, or core's ErrorLogFormat when errorLog is set:
// modifiers and {arguments}, then a known handler. ok is false where the
// format is malformed or uses an unsupported handler.
func apacheLogItemAt(format string, i int, errorLog bool) (item apacheLogItem, next int, ok bool) {
	for i++; i < len(format); {
		switch c := format[i]; {
		case c >= '0' && c <= '9':
			level := 0
			for i < len(format) && format[i] >= '0' && format[i] <= '9' {
				// Only error-log levels up to trace8 are meaningful.
				if level <= 15 {
					level = level*10 + int(format[i]-'0')
				}
				i++
			}
			if errorLog {
				item.level = level
			}
		case !errorLog && (c == '!' || c == '<' || c == '>' || c == ','):
			i++
		case errorLog && (c == '+' || c == '-'):
			item.required = item.required || c == '+'
			i++
		case c == '{':
			end := strings.IndexByte(format[i+1:], '}')
			if end < 0 {
				return item, 0, false
			}
			item.arg = format[i+1 : i+1+end]
			i += end + 2
		case c == '^' && !errorLog:
			if i+3 > len(format) {
				return item, 0, false
			}
			item.handler = format[i : i+3]
			return item, i + 3, item.handler == "^ti" || item.handler == "^to"
		default:
			item.handler = format[i : i+1]
			return item, i + 1, apacheLogHandlerKnown(item.handler, errorLog)
		}
	}
	return item, 0, false
}

// Module-defined handlers outside this grammar are ambiguous, even after
// the normal peer field: their output framing is not known here.
func apacheLogHandlerKnown(handler string, errorLog bool) bool {
	known := "aAhbBCDefHiIklLmnoOpPqrRsStTuUvVxX"
	if errorLog {
		known = "aAeEFiklLmnMPtTvV"
	}
	return len(handler) == 1 && strings.IndexByte(known, handler[0]) >= 0
}

// Custom strftime formats may emit newlines, tabs or an empty value. Only
// a nonempty, whitespace-free expansion can be treated as an opaque token.
// Other time formats are ambiguous; do not guess their output boundaries.
func apacheTimeTokenStable(arg string) bool {
	if arg == "" || arg == "begin" || arg == "end" {
		return true
	}
	arg = strings.TrimPrefix(strings.TrimPrefix(arg, "begin:"), "end:")
	if arg == "" {
		return true
	}
	for i := 0; i < len(arg); i++ {
		if arg[i] == ' ' || arg[i] == '\n' || logWhitespace(arg[i]) {
			return false
		}
		if arg[i] == '%' {
			i++
			if i == len(arg) || !strings.ContainsRune("%CdDFgGHIjmMSsRTuUVwWyYz", rune(arg[i])) {
				return false
			}
		}
	}
	return true
}

// apacheTimeNewline reports whether a time argument can write a line
// break: a raw newline, or strftime's %n with glibc flags, width and E/O
// in that order. A flag after the width is an unknown literal conversion.
func apacheTimeNewline(arg string) bool {
	if strings.IndexByte(arg, '\n') >= 0 {
		return true
	}
	for i := 0; i < len(arg); i++ {
		if arg[i] != '%' {
			continue
		}
		j := i + 1
		for j < len(arg) && strings.IndexByte("_-0^#", arg[j]) >= 0 {
			j++
		}
		for j < len(arg) && arg[j] >= '0' && arg[j] <= '9' {
			j++
		}
		if j < len(arg) && (arg[j] == 'E' || arg[j] == 'O') {
			j++
		}
		if j < len(arg) && arg[j] == 'n' {
			return true
		}
		i = j
	}
	return false
}

// These handlers write an unrecognized argument verbatim. Restrict them
// to their documented forms rather than assuming a nonempty server token.
func apacheAccessArgumentKnown(item apacheLogItem) bool {
	arg := strings.ToLower(item.arg)
	switch item.handler {
	case "p":
		return arg == "" || arg == "canonical" || arg == "local" || arg == "remote"
	case "P":
		return arg == "" || arg == "pid" || arg == "tid" || arg == "hextid"
	case "T":
		return arg == "" || arg == "s" || arg == "ms" || arg == "us"
	}
	return true
}

// apacheAccessLogSafe reports whether an access-log placeholder writes the
// connection's peer or a value the server sets.
func apacheAccessLogSafe(item apacheLogItem) bool {
	switch item.handler {
	case "a", "h":
		return item.arg == "" || item.arg == "c"
	case "A", "b", "B", "D", "I", "k", "L", "O", "p", "P", "s", "S", "t", "T", "v", "X":
		return true
	}
	return false
}

// addressStartByte reports whether c can begin an address CSM parses: a
// token that starts with any other byte is never read as a client.
func addressStartByte(c byte) bool {
	return c == '[' || c == ':' || c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// logWhitespace reports whether c is whitespace other than the space that
// ends a field. A reader may trim it, so it never guards a field.
func logWhitespace(c byte) bool {
	return c == '\t' || c == '\r' || c == '\v' || c == '\f'
}

// apacheFormatLogsClientValue reports whether an Apache access format
// writes a value the request chooses where CSM reads the client: the first
// field of each line, or the second when splitlogs strips the first. A
// read field that starts with a literal no address starts with is safe; a
// stripped field is not, since a value with spaces shifts the next field.
// Leading whitespace cannot finish the first token; a newline resets the
// read position. Unsupported output boundaries leave ok false.
func apacheFormatLogsClientValue(format string, splitlogs bool) (value, ok bool) {
	read := 0
	if splitlogs {
		read = 1
	}
	field, start, guarded := 0, true, false
	literal := func(c byte) {
		if start && !logWhitespace(c) {
			guarded, start = !addressStartByte(c), false
		}
	}
	for i := 0; i < len(format); {
		c := format[i]
		switch {
		case c == '%' && i+1 < len(format) && format[i+1] == '%':
			literal('%')
			i += 2
		case c == '%':
			item, next, parsed := apacheLogItemAt(format, i, false)
			if !parsed {
				return false, false
			}
			// A line break anywhere starts a record whose first field is
			// read; other framing matters only up to the read field.
			if item.handler == "t" && apacheTimeNewline(item.arg) {
				return false, false
			}
			if field <= read && (item.handler == "t" && !apacheTimeTokenStable(item.arg) || !apacheAccessArgumentKnown(item)) {
				return false, false
			}
			start = false
			if !apacheAccessLogSafe(item) && (field < read || field == read && !guarded) {
				value = true
			}
			i = next
		case c == '\n':
			field, start, guarded = 0, true, false
			i++
		case c == '\\' && i+1 < len(format) && format[i+1] == 'n':
			field, start, guarded = 0, true, false
			i += 2
		case c == '\\' && i+1 < len(format) && strings.IndexByte(`\rt`, format[i+1]) >= 0:
			// \r and \t write whitespace, \\ a backslash.
			if format[i+1] == '\\' {
				literal('\\')
			} else {
				literal('\t')
			}
			i += 2
		case c == ' ':
			// splitlogs strips one field; the realtime reader then skips
			// leading whitespace before choosing its first token.
			if !start {
				field++
			}
			start, guarded = true, false
			i++
		default:
			literal(c)
			i++
		}
	}
	return value, true
}

// LiteSpeed shares the common Apache format, but not its whole grammar.
// Unknown escapes lose their backslash, unsupported items can disappear,
// and brace arguments can select request variables even on server items.
// Only reuse Apache's field analysis where both dialects agree.
func liteSpeedFormatLogsClientValue(format string, splitlogs bool) (value, ok bool) {
	for i := 0; i < len(format); {
		switch format[i] {
		case '\\':
			if i+1 == len(format) || !strings.ContainsRune(`\rnt"'`, rune(format[i+1])) {
				return false, false
			}
			i += 2
		case '%':
			if i+1 < len(format) && format[i+1] == '%' {
				i += 2
				continue
			}
			item, next, parsed := apacheLogItemAt(format, i, false)
			if !parsed || len(item.handler) != 1 || strings.IndexByte("aABbCDefhHilmnopPqrstTuUvVXIOSx", item.handler[0]) < 0 {
				return false, false
			}
			modifiers := format[i+1 : next-1]
			if modifiers != "" && modifiers != "<" && modifiers != ">" && (item.arg == "" || modifiers != "{"+item.arg+"}") {
				return false, false
			}
			if !apacheAccessArgumentKnown(item) {
				return false, false
			}
			if item.arg != "" {
				switch item.handler {
				case "t":
					if !strings.Contains(item.arg, "%") && item.arg != "sec" && item.arg != "msec" && item.arg != "usec" && item.arg != "msec_frac" && item.arg != "usec_frac" {
						return false, false
					}
				case "a", "h":
					if item.arg != "c" {
						return false, false
					}
				case "p", "P", "T", "C", "e", "i", "n", "o", "x":
				default:
					return false, false
				}
			}
			i = next
		default:
			i++
		}
	}
	return apacheFormatLogsClientValue(format, splitlogs)
}

// apacheErrorLogSafe reports whether an ErrorLogFormat placeholder writes
// the connection's peer or a value the server sets.
func apacheErrorLogSafe(item apacheLogItem) bool {
	switch item.handler {
	case "a":
		return item.arg == "" || item.arg == "c"
	case "A", "E", "F", "k", "l", "L", "m", "P", "t", "T", "v":
		return true
	}
	return false
}

// A missing or level-filtered error item erases its whole field, including
// an earlier %M. A message emitted while a field is skipping can also be
// erased in the next field. Trust messages only when their fields contain
// no other placeholders. Unusual shared fields stay conservative.
func apacheErrorMessagesStable(format string) bool {
	message, other := false, false
	for i := 0; i < len(format); {
		if format[i] == ' ' {
			message, other = false, false
		}
		if format[i] == '%' {
			if i+1 < len(format) && format[i+1] == ' ' {
				message, other = false, false
				i += 2
				continue
			}
			if i+1 < len(format) && format[i+1] == '%' {
				i += 2
				continue
			}
			item, next, parsed := apacheLogItemAt(format, i, true)
			if !parsed {
				return false
			}
			if item.handler == "M" {
				message = true
			} else {
				other = true
			}
			if message && other {
				return false
			}
			i = next
			continue
		}
		// Core keeps escaped spaces in a literal item. Only a raw space
		// starting the next item, or % , begins a new field.
		atStart := true
		for i < len(format) && format[i] != '%' && (format[i] != ' ' || atStart) {
			if format[i] == '\\' && i+1 < len(format) {
				i += 2
				continue
			}
			if format[i] != ' ' {
				atStart = false
			}
			i++
		}
	}
	return true
}

// apacheErrorFormatLogsClientValue reports whether an ErrorLogFormat
// writes a value the request chooses before the message in any record, where the
// ModSecurity reader looks for "[client ". ok is false where Apache
// refuses the format.
func apacheErrorFormatLogsClientValue(format string, main bool) (value, ok bool) {
	stableMessage := apacheErrorMessagesStable(format)
	message, seenMessage := false, false
	for i := 0; i < len(format); {
		switch {
		case format[i] == '\n':
			message = false
			i++
		case format[i] == '\\' && i+1 < len(format):
			// A new record has its own prefix before a message marker.
			if format[i+1] == 'n' {
				message = false
			}
			// Core consumes the escaped byte as a literal, including '%'.
			i += 2
		case format[i] == '%' && i+1 < len(format) && (format[i+1] == '%' || format[i+1] == ' '):
			i += 2
		case format[i] == '%':
			item, next, parsed := apacheLogItemAt(format, i, true)
			if !parsed {
				return false, false
			}
			// Only a line break can move the prefix the reader searches.
			if item.handler == "t" && apacheTimeNewline(item.arg) {
				return false, false
			}
			if item.level > 15 || main && item.required || !main && (item.level != 0 || item.handler == "M") {
				return false, false
			}
			if item.handler == "M" {
				seenMessage = true
				// A shared field may erase a message already written.
				if item.level == 0 && stableMessage {
					message = true
				}
			} else if !message && !apacheErrorLogSafe(item) {
				value = true
			}
			i = next
		default:
			i++
		}
	}
	return value, !main || seenMessage
}

// apacheSplitlogsPipe reports whether a log target pipes to cPanel's
// splitlogs, which strips the first field (the virtual host) of each line.
// A pipe that names splitlogs anywhere counts, wrappers included.
func apacheSplitlogsPipe(target string) bool {
	return strings.HasPrefix(target, "|") && strings.Contains(target, "splitlogs")
}

// apacheLogTargetUnresolved reports whether expansion can change whether a
// log target is a splitlogs pipe. Only a leading "|" pipes, so a variable in
// a file path is harmless; a leading variable followed by "/" names a log
// directory, as Debian's ${APACHE_LOG_DIR}/access.log does.
func apacheLogTargetUnresolved(target string) bool {
	switch {
	case !apacheArgumentHasVariable(target):
		return false
	case strings.HasPrefix(target, "|"):
		return !strings.Contains(target, "splitlogs")
	case !strings.HasPrefix(target, "${"):
		return false
	}
	end := strings.IndexByte(target, '}')
	return end < 0 || !strings.HasPrefix(target[end+1:], "/")
}

// apacheLogFormat is a format a directive defines or uses inline.
type apacheLogFormat struct {
	format    string
	directive string
	file      string
	scope     string
	condition string
}

func (f apacheLogFormat) availableIn(scope string, conditions ...string) bool {
	if f.scope != "" && f.scope != scope {
		return false
	}
	if f.condition == "" {
		return true
	}
	for _, condition := range conditions {
		// A log inside the same condition or a nested one cannot run
		// without the definition in the enclosing condition.
		if condition == f.condition || strings.HasPrefix(condition, f.condition+"\x1e") {
			return true
		}
	}
	return false
}

// apacheLogUse is a log that writes a named, inline or default format.
type apacheLogUse struct {
	transfer  bool
	splitlogs bool
	inline    apacheLogFormat
}

// apacheLogFormats collects the access formats an Apache tree defines and
// the logs that use them, and checks error-log formats as it reads them.
type apacheLogFormats struct {
	named     map[string][]apacheLogFormat
	defaults  []apacheLogFormat
	uses      []apacheLogUse
	rewrite   *apacheLogFormat
	malformed bool
	liteSpeed bool
}

func (l *apacheLogFormats) parse(format string, splitlogs bool) (bool, bool) {
	if l.liteSpeed {
		return liteSpeedFormatLogsClientValue(format, splitlogs)
	}
	return apacheFormatLogsClientValue(format, splitlogs)
}

// add reads one directive. Apache refuses a format it cannot parse even
// when no log uses it, so such a format leaves the tree unknown.
func (l *apacheLogFormats) add(line apacheConfigLine, fields []string, ctx apacheLineContext) {
	switch name := strings.ToLower(fields[0]); name {
	case "logformat", "customlog", "globallog", "transferlog", "errorlogformat", "servername":
		for i, arg := range fields[1:] {
			unresolved := apacheArgumentHasVariable(arg)
			if i == 0 && (name == "customlog" || name == "globallog" || name == "transferlog") {
				unresolved = apacheLogTargetUnresolved(arg)
			}
			if unresolved {
				// Expansion can change the format, nickname or pipe target.
				l.malformed = true
				return
			}
		}
	}
	def := apacheLogFormat{
		directive: strings.Join(fields, " "), file: line.File,
		scope: strings.Join(ctx.ScopeKey, "\x1e"), condition: ctx.Condition,
	}
	check := func(format string) bool {
		if _, ok := l.parse(format, false); !ok {
			l.malformed = true
			return false
		}
		return true
	}
	switch {
	case strings.EqualFold(fields[0], "LogFormat"):
		switch len(fields) {
		case 2:
			def.format = fields[1]
			if check(def.format) {
				l.defaults = append(l.defaults, def)
			}
		case 3:
			def.format = fields[1]
			if check(def.format) {
				if l.named == nil {
					l.named = make(map[string][]apacheLogFormat)
				}
				l.named[strings.ToLower(fields[2])] = append(l.named[strings.ToLower(fields[2])], def)
			}
		default:
			l.malformed = true
		}
	case strings.EqualFold(fields[0], "CustomLog") || strings.EqualFold(fields[0], "GlobalLog"):
		if len(fields) != 3 && len(fields) != 4 {
			l.malformed = true
			return
		}
		def.format = fields[2]
		// Apache parses this as a format before resolving its nickname.
		if !check(def.format) {
			return
		}
		if len(fields) == 4 {
			condition := fields[3]
			// Expressions need Apache's expression parser. An unparsed
			// or invalid condition cannot prove which configuration runs.
			if len(condition) < 5 || !strings.EqualFold(condition[:4], "env=") || condition[4:] == "!" {
				l.malformed = true
			}
		}
		l.uses = append(l.uses, apacheLogUse{splitlogs: apacheSplitlogsPipe(fields[1]), inline: def})
	case strings.EqualFold(fields[0], "TransferLog"):
		if len(fields) != 2 {
			l.malformed = true
			return
		}
		l.uses = append(l.uses, apacheLogUse{transfer: true, splitlogs: apacheSplitlogsPipe(fields[1]), inline: def})
	case strings.EqualFold(fields[0], "ServerName"):
		if len(fields) != 2 {
			l.malformed = true
			return
		}
		host := fields[1]
		if _, after, found := strings.Cut(host, "://"); found {
			host = after
		}
		host, _, _ = strings.Cut(host, ":")
		// Core accepts a blank host before a port. Its %v then writes no
		// token, leaving the following request field first.
		if strings.TrimSpace(host) == "" {
			l.malformed = true
		}
	case strings.EqualFold(fields[0], "ErrorLogFormat"):
		format := ""
		switch {
		case len(fields) == 2:
			format = fields[1]
		case len(fields) == 3 && (strings.EqualFold(fields[1], "connection") || strings.EqualFold(fields[1], "request")):
			format = fields[2]
		default:
			l.malformed = true
			return
		}
		value, ok := apacheErrorFormatLogsClientValue(format, len(fields) == 2)
		switch {
		case !ok:
			l.malformed = true
		case value && l.rewrite == nil:
			l.rewrite = &def
		}
	}
}

const apacheCommonLogFormat = `%h %l %u %t "%r" %>s %b`

// Every server starts with CLF. An override in another scope cannot prove
// that a log stopped using that built-in definition.
func (l *apacheLogFormats) withBuiltin(formats []apacheLogFormat, name string, source apacheLogFormat) []apacheLogFormat {
	if !strings.EqualFold(name, "CLF") {
		return formats
	}
	source.format = apacheCommonLogFormat
	return append(append([]apacheLogFormat(nil), formats...), source)
}

func (l *apacheLogFormats) resolve(source, use apacheLogFormat) []apacheLogFormat {
	named := l.named[strings.ToLower(source.format)]
	formats := l.withBuiltin(named, source.format, source)
	for _, def := range formats {
		if def.availableIn(use.scope, use.condition, source.condition) {
			return formats
		}
	}
	// A nickname in another scope may not exist for this log. Apache then
	// uses the argument itself as an inline format.
	return append(append([]apacheLogFormat(nil), formats...), source)
}

// clientValue returns the first format a log uses that writes a value the
// request chooses where CSM reads the client. A nickname no LogFormat
// defines is an inline format, as Apache reads it; TransferLog writes the
// default formats (or the formats they name), or the common log format
// when none is set.
func (l *apacheLogFormats) clientValue() *apacheLogFormat {
	if l.rewrite != nil {
		return l.rewrite
	}
	for _, use := range l.uses {
		var formats []apacheLogFormat
		switch {
		case use.transfer:
			defaultKnown := false
			for _, def := range l.defaults {
				defaultKnown = defaultKnown || def.availableIn(use.inline.scope, use.inline.condition)
			}
			// A default in another scope cannot replace this server's CLF.
			if !defaultKnown {
				def := use.inline
				def.format = apacheCommonLogFormat
				formats = append(formats, def)
			}
			for _, def := range l.defaults {
				// A one-argument LogFormat may name a format instead.
				formats = append(formats, l.resolve(def, use.inline)...)
			}
		default:
			formats = l.resolve(use.inline, use.inline)
		}
		for i := range formats {
			value, ok := l.parse(formats[i].format, use.splitlogs)
			if !ok {
				l.malformed = true
				continue
			}
			if value {
				return &formats[i]
			}
		}
	}
	return nil
}

// nginxSafeLogVariables are HTTP core values with server-owned output.
// Optional realip names are not proof of a peer: without that module,
// regex captures and extension modules can define them from request data.
var nginxSafeLogVariables = map[string]bool{
	"remote_addr": true, "remote_port": true, "server_addr": true,
	"server_port": true, "server_name": true, "hostname": true,
	"time_local": true, "time_iso8601": true, "msec": true, "pid": true,
	"connection": true, "connection_requests": true, "status": true,
	"body_bytes_sent": true, "bytes_sent": true, "request_length": true,
	"request_time": true, "pipe": true, "nginx_version": true,
}

// A name that is built in to HTTP may be a user variable in stream.
// Stream server_name also remains user-definable before nginx 1.25.5.
func nginxSafeLogVariable(module, name string) bool {
	if module == "http" {
		return nginxSafeLogVariables[name]
	}
	switch name {
	case "remote_addr", "remote_port",
		"server_addr", "server_port", "hostname", "time_local",
		"time_iso8601", "msec", "pid", "connection", "status", "bytes_sent", "nginx_version",
		"bytes_received", "session_time", "protocol":
		return true
	}
	return false
}

// nginxFormatLogsClientValue keeps output-field state across arguments,
// but parses each argument's variables separately, as nginx does. Without
// escaping, a later request value can inject a fresh log line.
func nginxFormatLogsClientValue(module, escape string, custom map[string]bool, formats ...string) (value, ok bool) {
	if escape != "default" && escape != "json" && escape != "none" {
		return false, false
	}
	field, start, guarded := 0, true, false
	for _, format := range formats {
		for i := 0; i < len(format); {
			c := format[i]
			switch c {
			case '$':
				j := i + 1
				braced := j < len(format) && format[j] == '{'
				if braced {
					j++
				}
				k := j
				for k < len(format) && (format[k] == '_' || format[k] >= '0' && format[k] <= '9' ||
					format[k] >= 'a' && format[k] <= 'z' || format[k] >= 'A' && format[k] <= 'Z') {
					k++
				}
				if k == j || braced && (k == len(format) || format[k] != '}') {
					return false, false
				}
				if strings.EqualFold(format[j:k], "binary_remote_addr") {
					return false, false
				}
				name := strings.ToLower(format[j:k])
				if (custom[name] || !nginxSafeLogVariable(module, name)) && (escape == "none" || field == 0 && !guarded) {
					value = true
				}
				switch name {
				case "server_name", "hostname", "remote_port", "realip_remote_port", "server_port":
					// These can be empty; the next token may still be first.
				default:
					start = false
				}
				if braced {
					k++
				}
				i = k
			case '\n':
				field, start, guarded = 0, true, false
				i++
			case ' ':
				if !start {
					field++
				}
				start, guarded = true, false
				i++
			default:
				if start && !logWhitespace(c) {
					guarded, start = !addressStartByte(c), false
				}
				i++
			}
		}
	}
	return value, true
}
