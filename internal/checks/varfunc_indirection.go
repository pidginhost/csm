package checks

import (
	"regexp"
)

// dangerousIndirectNames is the closed set of PHP identifiers that, when
// bound to a variable and invoked indirectly, indicate code execution
// the static-string detectors would otherwise miss. Decoder names cover
// the eval(base64_decode("...")) bypass; the exec primitives cover the
// "$r = 'system'; $r($_GET['c']);" pattern that command-runs without
// ever writing the literal call.
var dangerousIndirectNames = map[string]struct{}{
	"base64_decode":   {},
	"gzinflate":       {},
	"gzuncompress":    {},
	"gzdecode":        {},
	"bzdecompress":    {},
	"str_rot13":       {},
	"rawurldecode":    {},
	"eval":            {},
	"assert":          {},
	"system":          {},
	"passthru":        {},
	"exec":            {},
	"shell_exec":      {},
	"popen":           {},
	"proc_open":       {},
	"pcntl_exec":      {},
	"create_function": {},
}

// varAssignRe captures `$NAME = "VALUE"` or `$NAME = 'VALUE'`. It does
// not understand concatenation, encoded literals, or multi-line strings
// - the goal is to catch the common attacker shape, not every possible
// PHP escape. False negatives degrade gracefully; false positives are
// bounded by the dangerousIndirectNames allowlist below.
var varAssignRe = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']([A-Za-z_][A-Za-z0-9_]*)["']`)

// varCallRe captures `$NAME(`. Matches either a direct invocation or
// the inner call of `eval($NAME(` / `$other($NAME(` patterns.
var varCallRe = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)\s*\(`)

// detectVarFuncDangerousAssignment returns true when content contains a
// `$var = "dangerous_name"` assignment AND a corresponding `$var(`
// invocation. Both can sit on different lines. The check is bounded by
// the closed dangerousIndirectNames set so it does not light up on
// arbitrary string-keyed callables in legitimate code.
func detectVarFuncDangerousAssignment(content string) bool {
	bindings := map[string]struct{}{}
	for _, m := range varAssignRe.FindAllStringSubmatch(content, -1) {
		if _, ok := dangerousIndirectNames[m[2]]; ok {
			bindings[m[1]] = struct{}{}
		}
	}
	if len(bindings) == 0 {
		return false
	}
	for _, m := range varCallRe.FindAllStringSubmatch(content, -1) {
		if _, ok := bindings[m[1]]; ok {
			return true
		}
	}
	return false
}
