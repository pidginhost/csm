package checks

// PHPExecutableStructure returns executable PHP with comments, inline HTML,
// and string bodies blanked while preserving byte offsets and line breaks.
// It is suitable for confirming that a dangerous token is PHP syntax rather
// than documentation or sample text stored in a literal.
func PHPExecutableStructure(src string) string {
	return stripPHPStringsFromCode(PHPExecutableCode(src))
}
