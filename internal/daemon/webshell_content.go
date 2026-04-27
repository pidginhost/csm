package daemon

import "regexp"

// looksLikePHPWebshell returns true when PHP file content exhibits the
// canonical realtime-detectable webshell shapes:
//  1. A request superglobal ($_GET / $_POST / $_REQUEST / $_COOKIE /
//     php://input) flowing into a code-execution primitive
//     (eval / assert / system / passthru / exec / shell_exec / proc_open
//     / popen / create_function), with optional decoder layers
//     (base64_decode / gzinflate / str_rot13).
//  2. eval/assert wrapping a decoder of an arbitrary base64 / gzinflate
//     blob (the obfuscated-payload primitive).
//
// Returns false on legitimate code that uses dangerous functions in
// non-attack contexts (Pear Text_Diff/Engine/shell.php's shell_exec call
// to Unix `diff`, TinyMCE charmap.php's static glyph data array).
func looksLikePHPWebshell(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	// Cap the regex sweep at 64 KiB; webshells are tiny and we already
	// only read 65536 bytes from the fd. Keeps RE2 cost bounded on huge
	// legitimate files that happened to land here.
	if len(data) > 65536 {
		data = data[:65536]
	}
	for _, re := range webshellContentRegexes {
		if re.Match(data) {
			return true
		}
	}
	return requestVariableFlowsToDangerousFunction(data)
}

// webshellContentRegexes are the realtime-detection-grade content patterns
// for looksLikePHPWebshell. Compiled once at package init.
var webshellContentRegexes = []*regexp.Regexp{
	// Request superglobal directly piped into a code-execution primitive
	// in the same expression (with optional decoder layers).
	regexp.MustCompile(`(?i)\b(?:eval|assert|system|passthru|exec|shell_exec|proc_open|popen|create_function)\s*\(\s*(?:gzinflate\s*\(\s*|str_rot13\s*\(\s*|base64_decode\s*\(\s*|@\s*)*\s*\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b`),
	// php://input piped into eval/assert/system in the same expression.
	regexp.MustCompile(`(?i)\b(?:eval|assert|system|passthru|exec|shell_exec|proc_open|popen|create_function)\s*\(\s*(?:gzinflate\s*\(\s*|str_rot13\s*\(\s*|base64_decode\s*\(\s*|@\s*)*\s*file_get_contents\s*\(\s*['"]php://input`),
	// eval/assert wrapping a base64/gzinflate/str_rot13 decoder of a
	// long literal blob (obfuscated-payload primitive).
	regexp.MustCompile(`(?i)\b(?:eval|assert)\s*\(\s*(?:gzinflate\s*\(\s*|str_rot13\s*\(\s*)?base64_decode\s*\(\s*['"][A-Za-z0-9+/=]{40,}`),
}

var (
	requestAssignmentRegex     = regexp.MustCompile(`(?is)\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:@?\s*)?(?:\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b(?:\s*\[[^\]]{0,200}\])?|file_get_contents\s*\(\s*['"]php://input['"]\s*\))[^;]{0,200};`)
	dangerousVariableCallRegex = regexp.MustCompile(`(?is)\b(?:eval|assert|system|passthru|exec|shell_exec|proc_open|popen|create_function)\s*\(\s*(?:@?\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\b`)
)

func requestVariableFlowsToDangerousFunction(data []byte) bool {
	matches := requestAssignmentRegex.FindAllSubmatchIndex(data, -1)
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}
		varName := string(data[match[2]:match[3]])
		windowEnd := match[1] + 800
		if windowEnd > len(data) {
			windowEnd = len(data)
		}
		for _, call := range dangerousVariableCallRegex.FindAllSubmatch(data[match[1]:windowEnd], -1) {
			if len(call) == 2 && string(call[1]) == varName {
				return true
			}
		}
	}
	return false
}
