package phptaint

import (
	"fmt"

	"github.com/VKCOM/php-parser/pkg/ast"
	"github.com/VKCOM/php-parser/pkg/conf"
	"github.com/VKCOM/php-parser/pkg/errors"
	"github.com/VKCOM/php-parser/pkg/parser"
	"github.com/VKCOM/php-parser/pkg/version"
)

// parserVersion is the highest grammar this parser implements. Hosts run
// newer PHP; constructs beyond this ceiling recover into a partial tree and
// are accounted as coverage gaps rather than analysed.
const parserVersion = "8.1"

// parseSource returns the tree plus a status. StatusAnalyzed here means only
// that parsing completed cleanly; the data-flow pass decides the final status.
func parseSource(src []byte) (ast.Vertex, Status, string) {
	ver, err := version.New(parserVersion)
	if err != nil {
		return nil, StatusParseError, "parser version unavailable"
	}
	var syntaxErrs int
	var firstLine int
	root, err := parser.Parse(src, conf.Config{
		Version: ver,
		ErrorHandlerFunc: func(e *errors.Error) {
			syntaxErrs++
			if firstLine == 0 && e != nil && e.Pos != nil {
				firstLine = e.Pos.StartLine
			}
		},
	})
	switch {
	case err != nil:
		// parser.Parse currently returns only configuration errors here. Keep
		// this diagnostic generic so a future parser error cannot expose input.
		return nil, StatusParseError, "parser failed"
	case root == nil:
		return nil, StatusParseError, "parser produced no tree"
	case syntaxErrs > 0:
		reason := fmt.Sprintf("recovered from %d syntax error(s)", syntaxErrs)
		if firstLine > 0 {
			reason += fmt.Sprintf(" starting at line %d", firstLine)
		}
		return root, StatusPartialParse, sanitizeReason(reason)
	}
	return root, StatusAnalyzed, ""
}
