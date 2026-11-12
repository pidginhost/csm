package checks

import "strings"

// PHPRequestFlowStructure returns executable PHP with comments, inline HTML,
// and string bodies blanked while preserving byte offsets and line breaks.
// It is suitable for confirming that a dangerous token is PHP syntax rather
// than documentation or sample text stored in a literal. A literal whose
// whole value is php://input stays visible: the request body is the one
// request source PHP code names with a string.
func PHPRequestFlowStructure(src string) string {
	return stripPHPStringsKeeping(PHPExecutableCode(src), isPHPRequestBodyLiteral)
}

func isPHPRequestBodyLiteral(token string) bool {
	if len(token) < 2 || (token[0] != '\'' && token[0] != '"') || token[len(token)-1] != token[0] {
		return false
	}
	return strings.EqualFold(token[1:len(token)-1], "php://input")
}
