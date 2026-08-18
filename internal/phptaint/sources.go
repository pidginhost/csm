package phptaint

import (
	"strings"

	"github.com/VKCOM/php-parser/pkg/ast"
)

// alwaysRemote functions can only acquire content over the network.
var alwaysRemote = map[string]bool{
	"curl_exec":               true,
	"curl_multi_getcontent":   true,
	"wp_remote_retrieve_body": true,
	"fsockopen":               true,
}

// dualUse functions read either a local path or a remote URL, so their
// argument decides. fread, fgets and stream_get_contents are deliberately
// excluded: they take a stream resource, never a path, so their argument
// carries no locality signal. When the handle came from a remote fopen(),
// fopen is already the source and the tainted variable carries that
// through to the reader; scoring the reader too would only add false
// positives for handles opened on local paths.
var dualUse = map[string]bool{
	"file_get_contents": true,
	"fopen":             true,
	"readfile":          true,
}

// remoteSchemes mark an argument as remote. php:// and data:// are included
// because both deliver attacker-supplied bytes to an execution sink.
var remoteSchemes = []string{"http://", "https://", "ftp://", "ftps://", "php://", "data://"}

// localMarkers are PHP constructs that resolve to a path on this host.
var localMarkers = []string{"__dir__", "__file__", "dirname", "abspath",
	"get_template_directory", "plugin_dir_path", "realpath", "sys_get_temp_dir"}

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
	if !decidable {
		return localityUnknown
	}
	lower := strings.ToLower(text)
	for _, scheme := range remoteSchemes {
		if strings.Contains(lower, scheme) {
			return localityRemote
		}
	}
	for _, marker := range localMarkers {
		if strings.Contains(lower, marker) {
			return localityLocal
		}
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

// staticText folds an expression to text when every part is statically
// known. Constants and local-path helpers fold to their own names so
// argLocality can recognise them; a variable makes the whole expression
// undecidable.
//
// Recursion is depth-bounded because this is the one place the package
// recurses over attacker-controlled structure, and a Go stack overflow is
// fatal: recover() cannot catch it. Exceeding the bound yields "undecidable",
// which degrades to a reduced-confidence source rather than a wrong answer.
func staticText(n ast.Vertex) (string, bool) { return staticTextAt(n, 0) }

func staticTextAt(n ast.Vertex, depth int) (string, bool) {
	if depth > maxAnalysisDepth {
		return "", false
	}
	switch v := n.(type) {
	case *ast.ScalarString:
		return strings.Trim(string(v.Value), "\"'"), true
	case *ast.ExprBinaryConcat:
		left, okL := staticTextAt(v.Left, depth+1)
		right, okR := staticTextAt(v.Right, depth+1)
		if !okL || !okR {
			return "", false
		}
		return left + right, true
	case *ast.ExprConstFetch:
		return calleeName(v.Const), true
	case *ast.ExprFunctionCall:
		name := calleeName(v.Function)
		for _, marker := range localMarkers {
			if name == marker {
				return name, true
			}
		}
		return "", false
	case *ast.ScalarMagicConstant:
		return strings.ToLower(string(v.Value)), true
	}
	return "", false
}
