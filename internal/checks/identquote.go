package checks

import (
	"errors"
	"fmt"
)

// MySQL identifier limit per the manual is 64 bytes. Anything beyond
// is silently truncated by the server, but for the cleaner we want
// the failure to be loud at the validation step.
const mysqlIdentMaxLen = 64

// errEmptyIdent and errInvalidIdent are surfaced to the operator so
// the CLI prints a clear "the name you typed is not a valid MySQL
// identifier" instead of a SQL syntax error from the server.
var (
	errEmptyIdent   = errors.New("identifier is empty")
	errInvalidIdent = errors.New("identifier contains characters outside [A-Za-z0-9_$]")
	errLongIdent    = fmt.Errorf("identifier exceeds %d bytes (MySQL limit)", mysqlIdentMaxLen)
)

// QuoteIdent returns a backtick-quoted MySQL identifier, or an error
// if the input is empty, longer than 64 bytes, or contains characters
// outside the safe class. Used at every site where an attacker-
// controlled object name (trigger / event / routine / schema) would
// otherwise reach a SQL string concatenation.
//
// The safe class is intentionally narrow: standard MySQL allows more
// (digits-only names, dotted names, $-prefixed) but the cleaner only
// needs to handle CMS-shaped identifiers and operator-typed schema
// names. Rejecting anything weirder is cheaper than reasoning about
// edge cases in dynamic SQL.
func QuoteIdent(name string) (string, error) {
	if name == "" {
		return "", errEmptyIdent
	}
	if len(name) > mysqlIdentMaxLen {
		return "", errLongIdent
	}
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '$':
		default:
			return "", fmt.Errorf("%w: %q", errInvalidIdent, name)
		}
	}
	return "`" + name + "`", nil
}
