package checks

// IsWPVersionDataBytesComplete recognizes only literal assignments to the
// variables WordPress reads from its version file. Matching an installed copy
// alone cannot establish that a short-lived version probe carried no payload.
func IsWPVersionDataBytesComplete(buf []byte, complete bool) bool {
	if !complete || len(buf) == 0 {
		return false
	}
	s := &phpLiteralScanner{buf: buf}
	s.skipSpace()
	if !s.consumeOpener() {
		return false
	}
	version := false
	for {
		s.skipTrivia()
		if s.i == len(s.buf) {
			return version
		}
		if s.buf[s.i] != '$' {
			return false
		}
		s.i++
		name, ok := s.readIdent()
		if !ok {
			return false
		}
		switch name {
		case "wp_version", "wp_db_version", "tinymce_version", "required_php_version",
			"required_php_extensions", "required_mysql_version", "wp_local_package":
		default:
			return false
		}
		s.skipTrivia()
		if s.i == len(s.buf) || s.buf[s.i] != '=' {
			return false
		}
		s.i++
		s.skipTrivia()
		if name == "required_php_extensions" {
			if !s.parseTopArray() {
				return false
			}
		} else if !s.parseScalar() {
			return false
		}
		s.skipTrivia()
		if s.i == len(s.buf) || s.buf[s.i] != ';' {
			return false
		}
		s.i++
		version = version || name == "wp_version"
	}
}
