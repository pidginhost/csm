package contenttype

import "regexp"

// phpOpenTag matches the two PHP openers a web server executes under a stock
// configuration. The bare "<?" short tag is off by default and is also the
// XML and SVG declaration opener, so it is not treated as PHP here.
var phpOpenTag = regexp.MustCompile(`(?i)<\?(?:php(?:[ \t\r\n]|$)|=)`)

// HasPHPOpenTag reports whether data contains a PHP opening tag anywhere. It
// establishes PHP context for content whose name says nothing useful: an
// image carrying a payload, or a rule helper handed a file of unknown type.
func HasPHPOpenTag(data []byte) bool {
	return phpOpenTag.Match(data)
}
