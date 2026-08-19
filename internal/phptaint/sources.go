package phptaint

import (
	"strings"

	"github.com/VKCOM/php-parser/pkg/ast"
)

// alwaysRemote functions can only acquire content over the network.
var alwaysRemote = map[string]bool{
	"curl_exec":               true,
	"curl_multi_getcontent":   true,
	"wp_remote_get":           true,
	"wp_remote_retrieve_body": true,
	"fsockopen":               true,
}

// dualUse functions return either local or remote content, so their argument
// decides. fread, fgets and stream_get_contents are deliberately excluded:
// they take a stream resource, never a path, so their argument carries no
// locality signal. readfile is excluded because it returns a byte count, not
// the content it writes, so no fetched bytes can flow from its return value.
// For stream readers, the acquiring fopen or fsockopen call is already the
// source and its tainted handle carries through the expression.
var dualUse = map[string]bool{
	"file_get_contents": true,
	"fopen":             true,
}

// remoteSchemes mark an argument as remote. Only php://input is intrinsically
// request-controlled; php://memory, php://temp and local php://filter resources
// are not remote sources. A filter around a remote resource still contains its
// nested remote scheme and is classified accordingly.
var remoteSchemes = []string{"http://", "https://", "ftp://", "ftps://", "php://input", "data://"}

// These are the specific PHP and WordPress constructs whose result is known to
// be a local path. Arbitrary constants and calls remain undecidable: their
// runtime value can be a remote URL.
var (
	localPathConstants = map[string]bool{"abspath": true}
	localPathResults   = map[string]bool{
		"get_template_directory": true,
		"realpath":               true,
		"sys_get_temp_dir":       true,
	}
	pathTransforms = map[string]bool{
		"dirname":         true,
		"plugin_dir_path": true,
	}
)

type locality uint8

const (
	localityUnknown locality = iota
	localityLocal
	localityRemote
)

// sourceConfidence reports whether a call acquires remote content and how
// firmly that was shown.
func sourceConfidence(call *ast.ExprFunctionCall) (Confidence, bool) {
	name := calleeName(call.Function)
	if alwaysRemote[name] {
		return ConfidenceHigh, true
	}
	if !dualUse[name] {
		return ConfidenceLow, false
	}
	if len(call.Args) == 0 {
		return ConfidenceLow, true
	}
	arg, ok := call.Args[0].(*ast.Argument)
	if !ok {
		return ConfidenceLow, true
	}
	switch argLocality(arg.Expr) {
	case localityLocal:
		return ConfidenceLow, false
	case localityRemote:
		return ConfidenceHigh, true
	}
	return ConfidenceLow, true
}

// argLocality classifies an argument by shape. Literal text and
// concatenations of literals are decidable; anything else is unknown.
func argLocality(arg ast.Vertex) locality {
	text, decidable := staticText(arg)
	lower := strings.ToLower(text)
	for _, scheme := range remoteSchemes {
		if strings.Contains(lower, scheme) {
			return localityRemote
		}
	}
	if !decidable {
		return localityUnknown
	}
	if strings.HasPrefix(text, "/") || strings.HasPrefix(text, "./") ||
		strings.HasPrefix(text, "../") {
		return localityLocal
	}
	if text != "" {
		return localityLocal
	}
	return localityUnknown
}

// staticText folds an expression to text when every part is statically known.
// Known fragments survive an undecidable concatenation so a literal scheme can
// still prove remoteness; arbitrary constants and calls stay undecidable.
//
// Recursion is depth-bounded because this is the one place the package
// recurses over attacker-controlled structure, and a Go stack overflow is
// fatal: recover() cannot catch it. Exceeding the bound yields "undecidable",
// which degrades to a reduced-confidence source rather than a wrong answer.
func staticText(n ast.Vertex) (string, bool) { return staticTextAt(n, 0) }

func staticTextAt(n ast.Vertex, depth int) (string, bool) {
	if depth >= maxAnalysisDepth {
		return "", false
	}
	switch v := n.(type) {
	case *ast.ScalarString:
		raw := string(v.Value)
		if len(raw) < 2 || raw[0] != raw[len(raw)-1] || (raw[0] != '\'' && raw[0] != '"') {
			return raw, false
		}
		text := raw[1 : len(raw)-1]
		// Double-quoted PHP strings interpret hex, octal and other escapes.
		// Keeping visible fragments lets a literal scheme still prove remote,
		// but an escape makes the complete runtime text undecidable.
		if raw[0] == '"' && strings.ContainsRune(text, '\\') {
			return text, false
		}
		return text, true
	case *ast.ExprBinaryConcat:
		left, okL := staticTextAt(v.Left, depth+1)
		right, okR := staticTextAt(v.Right, depth+1)
		// Preserve known literal fragments even when another fragment is
		// dynamic. Separate undecidable pieces so two fragments cannot invent
		// a scheme across an unknown runtime value.
		if !okL || !okR {
			return left + "\x00" + right, false
		}
		return left + right, true
	case *ast.ExprBrackets:
		return staticTextAt(v.Expr, depth+1)
	case *ast.ExprConstFetch:
		name := calleeName(v.Const)
		if localPathConstants[name] {
			return name, true
		}
		return "", false
	case *ast.ExprFunctionCall:
		name := calleeName(v.Function)
		if localPathResults[name] {
			return name, true
		}
		if !pathTransforms[name] || len(v.Args) == 0 {
			return "", false
		}
		arg, ok := v.Args[0].(*ast.Argument)
		if !ok {
			return "", false
		}
		return staticTextAt(arg.Expr, depth+1)
	case *ast.ScalarMagicConstant:
		return strings.ToLower(string(v.Value)), true
	}
	return "", false
}
