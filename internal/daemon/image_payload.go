package daemon

import (
	"regexp"

	"github.com/pidginhost/csm/internal/contenttype"
)

// imagePayloadConstructs are the constructs that turn PHP bytes riding inside
// an image container into a working backdoor: a code or command sink, or a
// fetch of remote code to run. Each entry is reported verbatim as the
// finding's evidence, so the operator sees why the file was flagged.
//
// Every entry is a multi-character ASCII identifier. Compressed pixel data is
// random bytes, so a short punctuation shape turns up in ordinary plugin
// artwork by chance and cannot carry a rule: a shell-backtick arm measured
// here fired on a stock plugin layout preview whose pixel data also happened
// to hold a three-byte short-echo tag.
var imagePayloadConstructs = []struct {
	name string
	re   *regexp.Regexp
}{
	{"code execution sink", regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_>:$])(?:eval|assert|create_function|call_user_func(?:_array)?)\s*\(`)},
	{"command execution sink", regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_>:$])(?:system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(`)},
	{"file inclusion sink", regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_>:$])(?:include|require)(?:_once)?\s*[\s(]\s*[@$'"]`)},
	{"file write sink", regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_>:$])(?:file_put_contents|fwrite|fputs|move_uploaded_file)\s*\(`)},
	{"remote code fetch", regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_>:$])(?:curl_init|curl_exec|curl_setopt(?:_array)?|fsockopen|stream_context_create)\s*\(`)},
	{"remote code fetch", regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_>:$])(?:file_get_contents|fopen|readfile)\s*\(\s*['"]?(?:https?|ftp|php):`)},
	{"request-controlled input", regexp.MustCompile(`\$_(?:GET|POST|REQUEST|COOKIE|FILES)\s*\[`)},
}

// phpExecutableContent reports a PHP opening tag accompanied by a construct
// that executes or fetches code, and names the construct.
//
// A PHP opening tag alone is not evidence. Plugin screenshots quote one in
// their description chunks, and three bytes of it turn up in compressed pixel
// data by chance, so the construct beside it is what makes the verdict.
//
// It carries no opinion about the file type, so a caller that already knows a
// path has no business holding PHP can apply it to a tail read, where the
// container magic at offset zero is out of view.
func phpExecutableContent(data []byte) (string, bool) {
	if !contenttype.HasPHPOpenTag(data) {
		return "", false
	}
	for _, construct := range imagePayloadConstructs {
		if construct.re.Match(data) {
			return construct.name, true
		}
	}
	return "", false
}
