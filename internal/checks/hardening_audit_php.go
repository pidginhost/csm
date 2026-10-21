package checks

import "strings"

const (
	phpUploadProgressKey       = "session.upload_progress.enabled"
	phpFatalErrorBacktracesKey = "fatal_error_backtraces"
)

// FPM pool overrides are tracked only for the settings the audit evaluates.
var phpAuditPoolSettings = []string{phpUploadProgressKey, phpFatalErrorBacktracesKey}

// Keep conditional settings separate: disabling one site does not disable
// other sites that inherit PHP's global value.
type phpAuditINI map[string]map[string]string

func (ini phpAuditINI) merge(content string, pools bool) {
	scope := ""
	lines := strings.Split(content, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if end := strings.IndexByte(line, ']'); end > 0 {
				section := strings.TrimSpace(line[1:end])
				scope = ""
				if pools {
					scope = section
				} else if upper := strings.ToUpper(section); strings.HasPrefix(upper, "PATH") || strings.HasPrefix(upper, "HOST") {
					name := strings.TrimRight(strings.TrimLeft(section[4:], "= \t"), "/\\")
					if strings.HasPrefix(upper, "HOST") {
						name = strings.ToLower(name)
					}
					scope = upper[:4] + "=" + name
				}
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		// Quoted INI values can span lines. A directive-looking line inside
		// such a string must not override a real setting.
		start := i
		quote := phpAuditQuoteState(value, 0)
		for quote != 0 && i+1 < len(lines) {
			i++
			quote = phpAuditQuoteState(lines[i], quote)
		}
		if i > start {
			value += "\n" + strings.Join(lines[start+1:i+1], "\n")
		}
		if pools {
			if key = phpAuditPoolKey(key); key == "" {
				continue
			}
		}
		if ini[scope] == nil {
			ini[scope] = make(map[string]string)
		}
		ini[scope][key] = strings.TrimSpace(value)
	}
}

func phpAuditQuotesClosed(value string) bool {
	return phpAuditQuoteState(value, 0) == 0
}

func phpAuditQuoteState(value string, quote byte) byte {
	for i := 0; i < len(value); i++ {
		ch := value[i]
		switch {
		case quote == 0:
			if ch == ';' {
				return 0
			}
			if ch == '\'' || ch == '"' {
				quote = ch
			}
		case ch == quote:
			quote = 0
		case quote == '"' && ch == '\\' && i+1 < len(value):
			i++
		}
	}
	return quote
}

// phpAuditPoolKey maps a tracked pool directive to "admin:<setting>" or
// "value:<setting>", and anything else to "".
func phpAuditPoolKey(directive string) string {
	for _, setting := range phpAuditPoolSettings {
		switch directive {
		case "php_value[" + setting + "]", "php_flag[" + setting + "]":
			return "value:" + setting
		case "php_admin_value[" + setting + "]", "php_admin_flag[" + setting + "]":
			return "admin:" + setting
		}
	}
	return ""
}

// settingDisabled reports whether a boolean setting that defaults to on is
// explicitly off globally and not turned back on by any section or pool.
func (ini phpAuditINI) settingDisabled(key string, pools phpAuditINI) bool {
	value, set := ini[""][key]
	if !set || !phpAuditBoolDisabled(value) {
		return false
	}
	for _, settings := range ini {
		if value, set := settings[key]; set && !phpAuditBoolDisabled(value) {
			return false
		}
	}
	for _, settings := range pools {
		value, set := settings["admin:"+key]
		if !set {
			value, set = settings["value:"+key]
		}
		if set && !phpAuditBoolDisabled(value) {
			return false
		}
	}
	return true
}

func phpAuditBoolDisabled(raw string) bool {
	raw = stripPHPIniInlineComment(raw)
	if !phpAuditQuotesClosed(raw) || strings.Contains(raw, "${") {
		// PHP workers can have a different environment from the daemon.
		return false
	}
	value, expression := normalizePHPIniValueWithExpression(raw)
	if expression {
		n, ok := parsePHPIniIntExpression(value)
		return ok && n == 0
	}
	switch strings.ToLower(value) {
	case "", "off", "no", "false", "none":
		return true
	}
	// Unresolved constants are not proof of a disabled setting. Numeric
	// strings use PHP's leading-integer conversion, shared with the scanner.
	number := strings.TrimLeft(value, "+-")
	if number == "" || number[0] < '0' || number[0] > '9' {
		return false
	}
	return !phpIniBoolEnabled(raw)
}

// phpinfo lists the files actually parsed, including the expansion of empty
// PHP_INI_SCAN_DIR components to the compiled-in directory. Keep that order.
func phpAuditScannedFiles(info string) ([]string, bool) {
	var files []string
	found := false
	for _, line := range strings.Split(info, "\n") {
		switch {
		case strings.HasPrefix(line, "Additional .ini files parsed =>"):
			_, line, _ = strings.Cut(line, "=>")
			found = true
		case !found:
			continue
		case strings.TrimSpace(line) == "" || strings.Contains(line, "=>"):
			return files, true
		}
		for _, name := range strings.Split(line, ",") {
			if name = strings.TrimSpace(name); name != "" && name != "(none)" {
				files = append(files, name)
			}
		}
	}
	return files, found
}
