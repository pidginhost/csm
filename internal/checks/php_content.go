package checks

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// nestedEvalDecodeRe matches the PHP token sequence
// `<eval|assert> [ws] ( [ws] [@] [\] <ident> [ws] (`, with DOTALL so the
// source can have line breaks inside the whitespace gaps. Attackers wedge
// comments or common call modifiers between the sink and decoder; comments and
// strings are stripped before matching so only executable token structure is
// evaluated.
var nestedEvalDecodeRe = regexp.MustCompile(`(?is)\b(eval|assert)\s*\(\s*@?\s*\\?\s*(\w+)\s*\(`)

// reEvalVarCallee matches eval wrapping a variable function call,
// e.g. `eval($f(...))`. The literal-callee form above cannot capture a
// `$var` callee, yet eval'ing the result of a dynamic function call is a
// near-certain dropper signal in user web directories.
var reEvalVarCallee = regexp.MustCompile(`(?is)\beval\s*\(\s*@?\s*\$\w+\s*\(`)

// evalExecWrapInner lists code-construction primitives that, when wrapped
// directly by eval, indicate dynamic code execution rather than the
// decoder/decompressor chain nestedEvalDecodeRe already covers.
var evalExecWrapInner = map[string]struct{}{
	"create_function":      {},
	"call_user_func":       {},
	"call_user_func_array": {},
}

var callbackFirstArgFuncs = map[string]struct{}{
	"array_map":                  {},
	"call_user_func":             {},
	"call_user_func_array":       {},
	"register_shutdown_function": {},
	"register_tick_function":     {},
}

var callbackDangerousNames = map[string]struct{}{
	"assert":          {},
	"base64_decode":   {},
	"call_user_func":  {},
	"create_function": {},
	"eval":            {},
	"exec":            {},
	"gzinflate":       {},
	"gzuncompress":    {},
	"passthru":        {},
	"popen":           {},
	"proc_open":       {},
	"shell_exec":      {},
	"str_rot13":       {},
	"system":          {},
}

// reVarVarCall matches a variable-variable or dynamic-expression function
// invocation, e.g. `$$h(...)` or `${$x}(...)`. On its own this shows up in
// some dispatcher code, so it is only treated as an indicator when the same
// line also carries a request superglobal (the RCE shape).
var reVarVarCall = regexp.MustCompile(`(?:\$\$\w+|\$\{[^}]{1,64}\})\s*\(`)

const phpContentReadSize = 32768 // Read first 32KB for analysis

func hasBacktickSuperglobal(code string) bool {
	for i := 0; i < len(code); i++ {
		if isPHPQuote(code[i]) {
			i = skipPHPString(code, i)
			continue
		}
		if code[i] != '`' {
			continue
		}

		end := i + 1
		for end < len(code) {
			if code[end] == '\\' && end+1 < len(code) {
				end += 2
				continue
			}
			if code[end] == '`' {
				break
			}
			end++
		}
		if end >= len(code) {
			break
		}
		if containsRequestSuperglobal(code[i+1 : end]) {
			return true
		}
		i = end
	}
	return false
}

func hasCallbackExecName(code string) bool {
	for i := 0; i < len(code); i++ {
		if isPHPQuote(code[i]) {
			i = skipPHPString(code, i)
			continue
		}

		nameStart := i
		if code[i] == '\\' {
			if i+1 >= len(code) || !isPHPIdentifierStart(code[i+1]) || !canStartGlobalPHPFunction(code, i) {
				continue
			}
			nameStart = i + 1
		} else if !isPHPIdentifierStart(code[i]) || !canStartPHPFunctionName(code, i) {
			continue
		}

		nameEnd := nameStart + 1
		for nameEnd < len(code) && isPHPIdentifierPart(code[nameEnd]) {
			nameEnd++
		}
		name := code[nameStart:nameEnd]
		if _, ok := callbackFirstArgFuncs[name]; !ok {
			i = nameEnd - 1
			continue
		}

		openParen := skipPHPWhitespace(code, nameEnd)
		if openParen >= len(code) || code[openParen] != '(' {
			i = nameEnd - 1
			continue
		}
		firstArg := skipPHPWhitespace(code, openParen+1)
		if firstArg >= len(code) || !isPHPQuote(code[firstArg]) {
			i = nameEnd - 1
			continue
		}
		callbackName, _, ok := readPHPFunctionString(code, firstArg)
		if !ok {
			i = nameEnd - 1
			continue
		}
		if _, dangerous := callbackDangerousNames[callbackName]; dangerous {
			return true
		}
		i = nameEnd - 1
	}
	return false
}

func containsRequestSuperglobal(code string) bool {
	for _, requestVar := range []string{"$_request", "$_post", "$_get", "$_cookie", "$_server"} {
		if strings.Contains(code, requestVar) {
			return true
		}
	}
	return false
}

func canStartGlobalPHPFunction(code string, slash int) bool {
	if slash == 0 {
		return true
	}
	prev := code[slash-1]
	return !isPHPIdentifierPart(prev) && prev != '$' && prev != '>' && prev != ':' && prev != '\\'
}

func canStartPHPFunctionName(code string, start int) bool {
	if start == 0 {
		return true
	}
	prev := code[start-1]
	return !isPHPIdentifierPart(prev) && prev != '$' && prev != '>' && prev != ':' && prev != '\\'
}

// CheckPHPContent scans new/suspicious PHP files for obfuscation patterns,
// remote payload fetching, and eval chains. This is designed to catch droppers
// like the LEVIATHAN attack's file.php and files.php that use goto spaghetti,
// hex-encoded strings, and call_user_func with string-built function names.
//
// This check scans PHP files in directories that shouldn't normally contain
// user-authored PHP: wp-content/languages, wp-content/upgrade, wp-content/mu-plugins,
// and also checks any PHP files flagged by the file index as new.
func CheckPHPContent(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	homeDirs, err := GetScanHomeDirs(ctx)
	if err != nil {
		return nil
	}

	for _, homeEntry := range homeDirs {
		if ctx.Err() != nil {
			return findings
		}
		if !homeEntry.IsDir() {
			continue
		}
		homeDir := filepath.Join("/home", homeEntry.Name())

		// Get all potential document roots
		docRoots := []string{filepath.Join(homeDir, "public_html")}
		subDirs, _ := osFS.ReadDir(homeDir)
		for _, sd := range subDirs {
			if sd.IsDir() && sd.Name() != "public_html" && sd.Name() != "mail" &&
				!strings.HasPrefix(sd.Name(), ".") && sd.Name() != "etc" &&
				sd.Name() != "logs" && sd.Name() != "ssl" && sd.Name() != "tmp" {
				docRoots = append(docRoots, filepath.Join(homeDir, sd.Name()))
			}
		}

		for _, docRoot := range docRoots {
			// Scan directories that shouldn't contain user PHP
			suspiciousDirs := []string{
				filepath.Join(docRoot, "wp-content", "languages"),
				filepath.Join(docRoot, "wp-content", "upgrade"),
				filepath.Join(docRoot, "wp-content", "mu-plugins"),
				filepath.Join(docRoot, "wp-content", "plugins"),
				filepath.Join(docRoot, "wp-content", "themes"),
			}

			for _, dir := range suspiciousDirs {
				scanDirForObfuscatedPHP(ctx, dir, 4, cfg, &findings)
				if ctx.Err() != nil {
					return findings
				}
			}
		}
	}

	return findings
}

// scanDirForObfuscatedPHP recursively scans directories for PHP files with
// malicious content patterns.
func scanDirForObfuscatedPHP(ctx context.Context, dir string, maxDepth int, cfg *config.Config, findings *[]alert.Finding) {
	if ctx.Err() != nil {
		return
	}
	if maxDepth <= 0 {
		return
	}
	entries, err := osFS.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		name := entry.Name()
		fullPath := filepath.Join(dir, name)

		// Check suppressed paths
		suppressed := false
		for _, ignore := range cfg.Suppressions.IgnorePaths {
			if matchGlob(fullPath, ignore) {
				suppressed = true
				break
			}
		}
		if suppressed {
			continue
		}

		if entry.IsDir() {
			scanDirForObfuscatedPHP(ctx, fullPath, maxDepth-1, cfg, findings)
			continue
		}

		nameLower := strings.ToLower(name)
		if !strings.HasSuffix(nameLower, ".php") {
			continue
		}

		// Skip known safe files
		if IsSafePHPInWPDir(fullPath, name) {
			continue
		}

		// Read and analyze content
		result := analyzePHPContent(fullPath)
		if result.severity >= 0 {
			info, _ := osFS.Stat(fullPath)
			details := result.details
			if info != nil {
				details += fmt.Sprintf("\nSize: %d, Mtime: %s", info.Size(), info.ModTime().Format("2006-01-02 15:04:05"))
			}
			*findings = append(*findings, alert.Finding{
				Severity: result.severity,
				Check:    result.check,
				Message:  fmt.Sprintf("%s: %s", result.message, fullPath),
				Details:  details,
				FilePath: fullPath,
			})
		}
	}
}

type phpAnalysisResult struct {
	severity alert.Severity
	check    string
	message  string
	details  string
	readOK   bool
}

// analyzePHPContent reads the first phpContentReadSize bytes of a PHP file
// and checks for obfuscation and malicious patterns.
func analyzePHPContent(path string) phpAnalysisResult {
	f, err := osFS.Open(path)
	if err != nil {
		return phpAnalysisResult{severity: -1}
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, phpContentReadSize)
	n, _ := f.Read(buf)
	if n == 0 {
		return phpAnalysisResult{severity: -1}
	}
	content := string(buf[:n])
	contentLower := strings.ToLower(content)

	var indicators []string

	// --- Critical: Remote payload fetching ---
	// Paste sites are always suspicious in PHP files.
	// GitHub raw URLs are common in legitimate plugin update checkers,
	// so only count them as indicators when they appear on the same line
	// as a dangerous PHP function call.
	pasteHosts := []string{
		"pastebin.com/raw",
		"paste.ee/r/",
		"ghostbin.co/paste/",
		"hastebin.com/raw/",
	}
	for _, host := range pasteHosts {
		if strings.Contains(contentLower, host) {
			indicators = append(indicators, fmt.Sprintf("remote payload URL: %s", host))
		}
	}
	githubHosts := []string{"gist.githubusercontent.com", "raw.githubusercontent.com"}
	dangerousCalls := []string{"file_put_contents(", "fwrite(", "shell_", "passthru(", "popen("}
	for _, host := range githubHosts {
		if !strings.Contains(contentLower, host) {
			continue
		}
		// Same-line = strong signal (critical)
		sameLine := false
		for _, line := range strings.Split(contentLower, "\n") {
			if !strings.Contains(line, host) {
				continue
			}
			for _, fn := range dangerousCalls {
				if strings.Contains(line, fn) {
					indicators = append(indicators, fmt.Sprintf("remote payload URL with dangerous call: %s", host))
					sameLine = true
					break
				}
			}
			if sameLine {
				break
			}
		}
		// Co-presence (different lines, same 32 KB window) was previously
		// emitted as a weaker indicator. It generated standing FPs on
		// legit plugins that fetch upstream resources from github mirrors
		// (wp-statistics GeoLite2 updates, unyson font fetcher, polylang
		// language packs). Same-line is the strong signal kept above; the
		// co-presence path is removed entirely.
	}

	// --- Critical: eval() chains with decoding ---
	// Only flag when eval directly wraps a decoder (structural nesting),
	// not when they merely co-exist in the same file (which causes false
	// positives on legitimate plugins that use eval for templates and
	// base64_decode for unrelated data processing).
	decoders := []string{
		"base64_decode", "gzinflate", "gzuncompress", "str_rot13",
		"rawurldecode", "gzdecode", "bzdecompress",
	}
	hasDecoder := false
	hasNestedEvalDecode := false
	for _, d := range decoders {
		if strings.Contains(contentLower, d) {
			hasDecoder = true
		}
	}
	// Check for structural nesting: eval(base64_decode(...)), eval(gzinflate(...)), etc.
	// PHP tolerates inline comments and arbitrary whitespace (including line
	// breaks) between the keyword and its open paren, so a naive line-by-line
	// `eval(` substring scan misses `eval /*x*/ ( base64_decode(...))` and
	// `eval // bypass\n( base64_decode(...))`. Strip PHP comments and
	// strings first, then match the structural pattern across whitespace,
	// and require the inner callee to be one of the known decoders /
	// decompressors.
	commentStripped := stripPHPCommentsFromCode(contentLower)
	codeLower := stripPHPStringsFromCode(commentStripped)
	for _, m := range nestedEvalDecodeRe.FindAllStringSubmatch(codeLower, -1) {
		if len(m) < 3 {
			continue
		}
		inner := m[2]
		for _, d := range decoders {
			if inner == d {
				hasNestedEvalDecode = true
				break
			}
		}
		if hasNestedEvalDecode {
			break
		}
	}
	if hasNestedEvalDecode {
		indicators = append(indicators, "eval() directly wrapping encoding/compression function")
	}

	// eval wrapping dynamic code construction the decoder loop above
	// ignores: a variable callee (eval($f(...))) or a code-building
	// primitive (eval(create_function(...)), eval(call_user_func(...))).
	// These never appear in legitimate user-directory PHP; a single hit is
	// surfaced as a High signal (the >=2 gate still governs quarantine).
	hasEvalExecWrap := reEvalVarCallee.MatchString(codeLower)
	if !hasEvalExecWrap {
		for _, m := range nestedEvalDecodeRe.FindAllStringSubmatch(codeLower, -1) {
			if len(m) < 3 {
				continue
			}
			if m[1] != "eval" {
				continue
			}
			if _, ok := evalExecWrapInner[m[2]]; ok {
				hasEvalExecWrap = true
				break
			}
		}
	}
	if hasEvalExecWrap {
		indicators = append(indicators, "eval() wrapping a dynamic code-execution primitive")
	}

	// Backtick shell execution with request input -- `...$_GET...`.
	// Match only executable backtick spans, not quoted examples.
	if hasBacktickSuperglobal(commentStripped) {
		indicators = append(indicators, "backtick shell execution with request input")
	}

	// Callback-position exec: an exec/decoder function name passed as a
	// string callback (array_map("system", ...), register_shutdown_function(
	// "passthru", ...)). Runs on the comment-stripped source so the literal
	// callback name is preserved.
	if hasCallbackExecName(commentStripped) {
		indicators = append(indicators, "exec/decoder function name passed as a callback")
	}

	// Variable-variable / dynamic-expression function call co-located with
	// request input on the same line -- $$h($_GET[...]) -- a dynamic-dispatch
	// RCE shape. The same-line request-var gate keeps benign dispatcher code
	// (which uses $$var without attacker input) from tripping.
	for _, line := range strings.Split(codeLower, "\n") {
		if reVarVarCall.MatchString(line) && lineContainsRequestVar(line) {
			indicators = append(indicators, "variable-variable function call with request input")
			break
		}
	}

	// --- Critical: call_user_func with string-built function names ---
	// LEVIATHAN droppers build the target function name on the call itself:
	//   call_user_func("\x63"."\x75"."\x72"."\x6c", $payload)  ==  call_user_func("curl", ...)
	// File-wide hex/concat counts are unsafe here: WPML bundles PHPZip
	// (inc/wpml_zip.php) which declares 20+ ZIP-format signature constants
	// as hex literals ("\x50\x4b\x03\x04" etc.) and makes a single benign
	// call_user_func(self::$temp) call to invoke a temp-file factory.
	// Match the obfuscation on the callable target argument itself.
	if strings.Contains(contentLower, "call_user_func") {
		foundCallUserFuncObfuscation := false
		for _, line := range strings.Split(content, "\n") {
			if !strings.Contains(strings.ToLower(line), "call_user_func") {
				continue
			}
			for _, targetArg := range phpCallUserFuncTargetArgs(line) {
				// PHP 7+ accepts both "\xNN" hex and "\u{NN}" unicode-codepoint
				// escapes inside double-quoted strings. Treat them as
				// equivalent obfuscation forms so an attacker cannot bypass
				// the detector by swapping syntax.
				lineHex := countOccurrences(targetArg, `"\x`) + countOccurrences(targetArg, `"\u{`)
				lineConcat := countOccurrences(targetArg, `" . "`) + countOccurrences(targetArg, `"."`)
				// Typical shortest obfuscated name is 3-4 bytes ("exec", "curl",
				// "eval"); require >=3 escapes AND >=2 concatenations on the
				// call target argument.
				if lineHex >= 3 && lineConcat >= 2 {
					indicators = append(indicators, "call_user_func with obfuscated function names")
					foundCallUserFuncObfuscation = true
					break
				}
			}
			if foundCallUserFuncObfuscation {
				break
			}
		}
	}

	// --- High: Goto obfuscation (LEVIATHAN signature) ---
	gotoCount := countOccurrences(contentLower, "goto ")
	if gotoCount > 10 {
		indicators = append(indicators, fmt.Sprintf("excessive goto statements (%d found - obfuscation pattern)", gotoCount))
	}

	// --- High: Hex-encoded string construction ---
	// Only flag hex strings when accompanied by concatenation - real obfuscation
	// builds function names like "\x63" . "\x75" . "\x72" . "\x6c" (= "curl").
	// Standalone hex arrays (Wordfence IPv6 subnet masks, binary data) are benign.
	hexStringCount := countOccurrences(content, `"\x`)
	dotConcatCount := countOccurrences(content, `" . "`)
	if hexStringCount > 20 && dotConcatCount > 10 {
		indicators = append(indicators, fmt.Sprintf("heavy hex-encoded strings with concatenation (%d hex, %d concat - obfuscation pattern)", hexStringCount, dotConcatCount))
	}
	// The standalone "concat>30 alone" branch was removed: WordPress
	// themes and page builders concatenate literal CSS/HTML tokens
	// dozens of times in dynamic style/markup builders (sydney theme,
	// elementor, beaver builder), producing FPs on every install. Real
	// function-name obfuscation always pairs concat with hex escapes
	// and is still caught by the combined branch above.

	// --- Critical: variable-function indirection that resolves to a
	// decoder. Attackers slip past the literal "eval(base64_decode("
	// detector by binding the dangerous name to a variable on one line
	// and calling it on another:
	//     $d = "base64_decode";
	//     $r = "eval";
	//     $r($d("AAAA"));
	// The heuristic looks for an assignment $var = "decoder_or_exec"
	// followed by a $var( invocation in the same file. Hits must
	// reference at least one decoder OR one shell-exec primitive,
	// since plain variable function calls show up in legitimate
	// metaprogramming.
	if detectVarFuncDangerousAssignment(content) {
		indicators = append(indicators, "variable function name resolves to decoder or exec primitive")
	}

	// --- High: Variable function calls with obfuscated names ---
	// call_user_func + decoder alone is too broad - Elementor, WooCommerce, and
	// dozens of plugins use call_user_func_array with base64_decode legitimately.
	// Only flag when combined with actual obfuscation (hex strings, heavy concat).
	if strings.Contains(contentLower, "call_user_func") && hasDecoder {
		if hexStringCount > 5 || dotConcatCount > 5 {
			indicators = append(indicators, "variable function call with decoder and obfuscation")
		}
	}

	// --- High: Shell execution functions combined with request input ---
	// Uses containsStandaloneFunc to avoid substring false positives
	// (e.g. "WP_Filesystem(" matching "exec(", "preg_match(" matching "exec(")
	shellFuncs := []string{"system(", "passthru(", "exec(", "shell_exec(", "popen(", "proc_open(", "pcntl_exec("}
	requestVars := []string{"$_request", "$_post", "$_get", "$_cookie", "$_server"}
	// Two-tier detection:
	// Same line = CRITICAL signal (auto-quarantine eligible)
	// Co-presence = HIGH signal (alert only, not quarantined alone)
	// This prevents bypass by splitting across lines while avoiding
	// false-positive quarantine of legitimate plugins.
	hasShellFunc := false
	hasRequestVar := false
	sameLineShellRequest := false
	for _, sf := range shellFuncs {
		if containsStandaloneFunc(contentLower, sf) {
			hasShellFunc = true
			break
		}
	}
	for _, rv := range requestVars {
		if strings.Contains(contentLower, rv) {
			hasRequestVar = true
			break
		}
	}
	// Same-line is a strong signal on its own: "$ret = system($_POST['cmd']);"
	// almost never occurs in legitimate code. Co-presence is weaker: elFinder
	// and other media-processing libraries legitimately call exec() for
	// ImageMagick and also consume $_POST for AJAX routing, placing both
	// tokens in the same 32 KB window. The co-presence finding is therefore
	// only emitted as CORROBORATION after all the stronger indicators have
	// been collected -- see the deferred append further below.
	coPresenceCandidate := false
	if hasShellFunc && hasRequestVar {
		for _, line := range strings.Split(contentLower, "\n") {
			lineHasShell := false
			for _, sf := range shellFuncs {
				if containsStandaloneFunc(line, sf) {
					lineHasShell = true
					break
				}
			}
			if !lineHasShell {
				continue
			}
			for _, rv := range requestVars {
				if strings.Contains(line, rv) {
					sameLineShellRequest = true
					break
				}
			}
			if sameLineShellRequest {
				break
			}
		}
		if sameLineShellRequest {
			indicators = append(indicators, "shell function with request input on same line")
		} else if !IsVerifiedCMSFile(path) {
			coPresenceCandidate = true
		}
	}

	// --- High: base64 encoding/decoding with execution on same line ---
	if strings.Contains(contentLower, "base64_decode") && strings.Contains(contentLower, "base64_encode") {
		for _, line := range strings.Split(contentLower, "\n") {
			hasBoth := strings.Contains(line, "base64_decode") && strings.Contains(line, "base64_encode")
			hasExec := false
			for _, sf := range shellFuncs {
				if containsStandaloneFunc(line, sf) {
					hasExec = true
					break
				}
			}
			if hasBoth && hasExec {
				indicators = append(indicators, "base64 encode+decode with execution on same line (command relay)")
				break
			}
		}
	}

	// Deferred corroboration: a lone co-presence is not enough. If a
	// stronger indicator was produced above, the co-presence is appended
	// both as extra context for the operator and to nudge the severity
	// into the >=2 Critical band for obfuscated droppers.
	if coPresenceCandidate && len(indicators) > 0 {
		indicators = append(indicators, "shell function co-present with request input")
	}

	// --- Determine severity based on indicators ---
	if len(indicators) == 0 {
		return phpAnalysisResult{severity: -1, readOK: true}
	}

	// Auto-quarantine in autoresponse.AutoQuarantineFiles acts only on
	// Critical findings. A single heuristic indicator has false-positive
	// classes severe enough to rm live production files (WPML's PHPZip
	// tripped the former "call_user_func with obfuscated" bypass on hex
	// constants that build ZIP magic bytes; legitimate plugins embed
	// pastebin URLs in support docstrings and release notes). Require
	// two converging indicators before the severity crosses the
	// destructive-action threshold; single hits surface as High and stay
	// in the operator queue.
	if len(indicators) >= 2 {
		return phpAnalysisResult{
			severity: alert.Critical,
			check:    "obfuscated_php",
			message:  "Obfuscated/malicious PHP detected",
			details:  fmt.Sprintf("Indicators found:\n- %s", strings.Join(indicators, "\n- ")),
			readOK:   true,
		}
	}

	return phpAnalysisResult{
		severity: alert.High,
		check:    "suspicious_php_content",
		message:  "Suspicious PHP content detected",
		details:  fmt.Sprintf("Indicators found:\n- %s", strings.Join(indicators, "\n- ")),
		readOK:   true,
	}
}

// IsSafePHPInWPDir returns true for known legitimate PHP files in WP directories
// like languages (translation files) and upgrade (empty index.php). Exported so
// the realtime fanotify path in internal/daemon shares the same allowlist as
// the polled fileindex scan; keeping the two in lock-step avoids the class of
// false positive where a path is recognised as safe by one path and flagged by
// the other. The name argument may be passed in any case; the function
// lower-cases it internally.
func IsSafePHPInWPDir(path, name string) bool {
	nameLower := strings.ToLower(name)

	// WordPress translation files: *.l10n.php, *.mo, admin-*.php patterns
	if strings.HasSuffix(nameLower, ".l10n.php") {
		return true
	}
	if nameLower == "index.php" {
		return true
	}

	// Known safe patterns in wp-content/languages/
	if strings.Contains(path, "/wp-content/languages/") {
		// Legitimate translation files have standard naming
		if strings.HasPrefix(nameLower, "admin-") ||
			strings.HasPrefix(nameLower, "continents-") ||
			strings.Contains(path, "/languages/plugins/") ||
			strings.Contains(path, "/languages/themes/") {
			return true
		}
		// WP 6.5+ PHP translation files: xx_XX.php format (2-5 letter locale codes)
		noExt := strings.TrimSuffix(nameLower, ".php")
		if strings.Contains(noExt, "_") && len(noExt) <= 10 && !strings.ContainsAny(noExt, " /.\\") {
			return true
		}
		// WPML translation queue: /wp-content/languages/wpml/queue/*.php
		// stores pure <?php return [...] arrays of translation strings.
		// Narrow match on the queue/ subdir, not on "wpml" anywhere in the
		// path, so a backdoor in /wp-content/languages/wpml/evil.php is
		// still caught.
		if strings.Contains(path, "/wp-content/languages/wpml/queue/") {
			return true
		}
	}

	// Known safe in mu-plugins - common hosting provider mu-plugins
	if strings.Contains(path, "/mu-plugins/") {
		safeMuPlugins := []string{
			"endurance", "starter", "imunify", "wp-toolkit",
			"starter-plugin", "starter_plugin",
			"jetpack", "object-cache", "redis-cache",
			"cloudlinux", "alt-php",
		}
		for _, safe := range safeMuPlugins {
			if strings.Contains(nameLower, safe) {
				return true
			}
		}
	}

	// Files in vendor/ or node_modules/ subdirectories within plugins/themes
	// are third-party dependencies and should not be flagged.
	if strings.Contains(path, "/wp-content/plugins/") || strings.Contains(path, "/wp-content/themes/") {
		if strings.Contains(path, "/vendor/") || strings.Contains(path, "/node_modules/") {
			return true
		}
	}

	return false
}

func countOccurrences(s, substr string) int {
	count := 0
	offset := 0
	for {
		idx := strings.Index(s[offset:], substr)
		if idx < 0 {
			break
		}
		count++
		offset += idx + len(substr)
	}
	return count
}

func phpCallUserFuncTargetArgs(line string) []string {
	lower := strings.ToLower(line)
	var args []string
	for _, name := range []string{"call_user_func_array", "call_user_func"} {
		searchFrom := 0
		for {
			pos := strings.Index(lower[searchFrom:], name)
			if pos < 0 {
				break
			}
			pos += searchFrom
			next := pos + len(name)
			searchFrom = next
			if !isPHPFuncNameBoundary(line, pos, next) {
				continue
			}
			i := skipPHPSpaceString(line, next)
			if i >= len(line) || line[i] != '(' {
				continue
			}
			if arg, ok := firstPHPCallArgument(line, i+1); ok {
				args = append(args, arg)
			}
		}
	}
	return args
}

func isPHPFuncNameBoundary(s string, start, end int) bool {
	if start > 0 {
		prev := s[start-1]
		if isIdentCont(prev) || prev == '>' || prev == ':' {
			return false
		}
	}
	return end >= len(s) || !isIdentCont(s[end])
}

func skipPHPSpaceString(s string, i int) int {
	for i < len(s) && isPHPSpace(s[i]) {
		i++
	}
	return i
}

func firstPHPCallArgument(s string, start int) (string, bool) {
	start = skipPHPSpaceString(s, start)
	i := start
	depth := 0
	var quote byte
	escaped := false
	for i < len(s) {
		c := s[i]
		if quote != 0 {
			if escaped {
				escaped = false
				i++
				continue
			}
			if c == '\\' {
				escaped = true
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			i++
			continue
		}

		switch c {
		case '"', '\'':
			quote = c
		case '(', '[', '{':
			depth++
		case ')':
			if depth == 0 {
				return s[start:i], true
			}
			depth--
		case ',':
			if depth == 0 {
				return s[start:i], true
			}
		}
		i++
	}
	return "", false
}

// containsStandaloneFunc reports whether content contains an occurrence of
// funcCall (e.g. "exec(") that is a real call to the named PHP function
// rather than something that shares the same suffix.
//
// Four shapes must be rejected:
//
//   - embedded identifiers: "doubleval(" must not match "eval("; the
//     preceding character is a letter/digit/underscore;
//   - method invocations: "$this->DB->exec(" must not match "exec(" even
//     though the preceding ">" is non-alphanumeric;
//   - static invocations: "Foo::exec(" must not match for the same reason;
//   - function declarations: "function exec(" names a local function of
//     the same name and must not be counted as a call site.
//
// The earlier implementation only guarded against the first case and was
// the source of false positives on elFinder volume drivers that call
// "$this->DB->exec(...)" (SQLite) alongside $_SERVER references on the
// same line.
func containsStandaloneFunc(content, funcCall string) bool {
	idx := 0
	for {
		pos := strings.Index(content[idx:], funcCall)
		if pos < 0 {
			return false
		}
		absPos := idx + pos
		nextIdx := absPos + len(funcCall)

		advance := func() bool {
			if nextIdx >= len(content) {
				return false
			}
			idx = nextIdx
			return true
		}

		if absPos == 0 {
			return true
		}

		prev := content[absPos-1]
		isAlnum := (prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z') ||
			(prev >= '0' && prev <= '9') || prev == '_'
		if isAlnum {
			if !advance() {
				return false
			}
			continue
		}

		if absPos >= 2 {
			op := content[absPos-2 : absPos]
			if op == "->" || op == "::" {
				if !advance() {
					return false
				}
				continue
			}
		} else if absPos == 1 && (prev == '>' || prev == ':') {
			// Degenerate position: only one preceding byte, and it is
			// the tail char of a possible method ("->") or static
			// ("::") operator. We cannot confirm the second char
			// because there is no second char. The conservative choice
			// is to skip, so a truncated "->exec(" or "::exec(" at the
			// very start of a buffer does not get flagged as a real
			// shell-function call.
			if !advance() {
				return false
			}
			continue
		}
		const decl = "function "
		if absPos >= len(decl) && content[absPos-len(decl):absPos] == decl {
			if !advance() {
				return false
			}
			continue
		}

		return true
	}
}

func containsAny(strs []string, substrs ...string) bool {
	for _, s := range strs {
		for _, sub := range substrs {
			if strings.Contains(s, sub) {
				return true
			}
		}
	}
	return false
}

// benignPHPStubMaxScan caps how many bytes of a candidate stub the
// recogniser will read. Stub files in the wild (BackWPup folder.php
// caches at ~160 KB, WP "silence is golden" index.php at ~30 B, plugin
// 404-stub headers under 1 KB) fit comfortably under this bound;
// anything larger must surface for normal alerting rather than be
// accepted on faith.
const benignPHPStubMaxScan = 4 * 1024 * 1024

// IsBenignPHPStub reports whether the reachable code region of a PHP
// file consists only of whitespace and comments, or terminates with a
// no-argument die / exit / __halt_compiler before any other statement.
// Files matching either shape cannot execute attacker-controlled code
// via a web request: PHP either runs to EOF emitting nothing, or hits
// the terminator and stops with the remaining bytes unreachable.
//
// The recogniser is content-shape only -- it does not look at the path,
// filename, parent directory, or whether a plugin is installed. An
// attacker cannot bypass it by naming a payload to mimic a known-plugin
// file because the gate fails the moment any executable statement
// appears before a terminator. Conversely a legitimate plugin that
// writes a stub-shaped working file (BackWPup writes
// "<?php //<json>" for job state and "<?php\n//path1\n//path2..." for
// folder caches) is recognised regardless of where it puts the file.
//
// Other detectors -- signature scans, YARA, suspicious filename, the
// webshell name list -- still run on the file in their own pipelines.
// Only the path-only "anomalous PHP location" warning is suppressed
// for files that this recogniser accepts.
func IsBenignPHPStub(path string) bool {
	f, err := osFS.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, benignPHPStubMaxScan)
	n, _ := f.Read(buf)
	if n == 0 {
		return false
	}
	info, err := f.Stat()
	complete := err == nil && info.Size() <= int64(n)
	return IsBenignPHPStubBytesComplete(buf[:n], complete)
}

// IsBenignPHPStubBytes is the buffer-only variant. The realtime fanotify
// path uses it on the bytes it already read from the file descriptor;
// IsBenignPHPStub provides the path-based entry point for the polled
// fileindex scan. Both rely on the same parser so realtime and scheduled
// scans agree on which files are stubs.
//
// The parser tokenises the leading region of the buffer:
//
//   - Optional UTF-8 BOM and whitespace, then the literal "<?php" opener.
//     The short-echo opener "<?=" is rejected because it emits output.
//     A "<?phpfoo" run-together opener is rejected because PHP requires
//     whitespace (or EOF) after the tag.
//   - Repeatedly accept whitespace, line comments ("//..." or "#..." up to
//     newline or "?>"), and balanced block comments ("/* ... */"). A "/*"
//     without a matching "*/" inside the scanned window is rejected -- we
//     cannot prove the rest of the file is comment.
//   - Accept the no-argument forms of die, exit, and __halt_compiler as
//     terminators. Once seen, the rest of the buffer is treated as
//     unreachable.
//   - Reject any closing "?>" tag (would allow HTML escape and a later
//     "<?php" re-entry that this gate does not analyse).
//   - Reject any other identifier (return, if, system, eval, function,
//     class, ...) and any stray punctuation ("$", "(", "=", ";", ...).
//     Those are statements we cannot prove benign.
//   - If the loop reaches EOF in a complete buffer having only seen
//     whitespace and comments, accept: PHP outputs nothing and executes
//     nothing.
func IsBenignPHPStubBytes(buf []byte) bool {
	return IsBenignPHPStubBytesComplete(buf, true)
}

// IsBenignPHPStubBytesComplete is like IsBenignPHPStubBytes, but complete
// tells the parser whether buf contains the entire file. Comment-only stubs
// require a complete buffer; no-argument terminators do not, because bytes
// after them are unreachable to PHP.
func IsBenignPHPStubBytesComplete(buf []byte, complete bool) bool {
	if len(buf) >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF {
		buf = buf[3:]
	}
	i := 0
	for i < len(buf) && isPHPSpace(buf[i]) {
		i++
	}
	const opener = "<?php"
	if !bytes.HasPrefix(buf[i:], []byte(opener)) {
		return false
	}
	i += len(opener)
	if i < len(buf) && !isPHPSpace(buf[i]) {
		return false
	}
	for i < len(buf) {
		c := buf[i]
		if isPHPSpace(c) {
			i++
			continue
		}
		if c == '#' {
			i = skipPHPLineComment(buf, i)
			continue
		}
		if c == '/' && i+1 < len(buf) && buf[i+1] == '/' {
			i = skipPHPLineComment(buf, i)
			continue
		}
		if c == '/' && i+1 < len(buf) && buf[i+1] == '*' {
			i += 2
			end := bytes.Index(buf[i:], []byte("*/"))
			if end < 0 {
				return false
			}
			i += end + 2
			continue
		}
		if c == '?' && i+1 < len(buf) && buf[i+1] == '>' {
			return false
		}
		if isIdentStart(c) {
			start := i
			for i < len(buf) && isIdentCont(buf[i]) {
				i++
			}
			word := strings.ToLower(string(buf[start:i]))
			return isNoArgPHPTerminator(buf, i, word, complete)
		}
		return false
	}
	return complete
}

func isPHPSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentCont(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

func skipPHPSpace(buf []byte, i int) int {
	for i < len(buf) && isPHPSpace(buf[i]) {
		i++
	}
	return i
}

func skipPHPLineComment(buf []byte, i int) int {
	for i < len(buf) {
		if buf[i] == '\n' {
			return i
		}
		if buf[i] == '?' && i+1 < len(buf) && buf[i+1] == '>' {
			return i
		}
		i++
	}
	return i
}

func isNoArgPHPTerminator(buf []byte, i int, word string, complete bool) bool {
	if word != "die" && word != "exit" && word != "__halt_compiler" {
		return false
	}
	i = skipPHPSpace(buf, i)

	if word == "__halt_compiler" {
		next, ok := consumeEmptyPHPParens(buf, i)
		if !ok {
			return false
		}
		return phpTerminatorStatementEnds(buf, next, complete)
	}

	if i >= len(buf) {
		return complete
	}
	if buf[i] == ';' {
		return true
	}
	if buf[i] == '?' && i+1 < len(buf) && buf[i+1] == '>' {
		return true
	}
	if buf[i] != '(' {
		return false
	}
	next, ok := consumeEmptyPHPParens(buf, i)
	if !ok {
		return false
	}
	return phpTerminatorStatementEnds(buf, next, complete)
}

func consumeEmptyPHPParens(buf []byte, i int) (int, bool) {
	if i >= len(buf) || buf[i] != '(' {
		return i, false
	}
	i = skipPHPSpace(buf, i+1)
	if i >= len(buf) || buf[i] != ')' {
		return i, false
	}
	return skipPHPSpace(buf, i+1), true
}

func phpTerminatorStatementEnds(buf []byte, i int, complete bool) bool {
	i = skipPHPSpace(buf, i)
	if i >= len(buf) {
		return complete
	}
	if buf[i] == ';' {
		return true
	}
	return buf[i] == '?' && i+1 < len(buf) && buf[i+1] == '>'
}
