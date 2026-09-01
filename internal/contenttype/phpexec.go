package contenttype

import "strings"

// executablePHPExtensions are the extensions a stock PHP-capable web server
// (Apache mod_php / PHP-FPM via EasyApache4, LiteSpeed LSAPI, Nginx + php-fpm)
// routes to the PHP interpreter by default. Any file with one of these names
// can execute PHP, so a content scan that skipped them would let a webshell
// hide behind a non-".php" name. ".phps" is deliberately excluded: the stock
// handler renders it as highlighted source, it does not execute. Lowercase,
// leading dot.
var executablePHPExtensions = []string{
	".php", ".php2", ".php3", ".php4", ".php5", ".php6", ".php7", ".php8",
	".phtml", ".pht",
}

// IsExecutablePHPExt reports whether ext (leading dot, any case) is one a
// stock PHP handler executes. Rule sets are written against ".php"; every
// extension here must be matched against the same rules or a payload hides
// behind the name.
func IsExecutablePHPExt(ext string) bool {
	ext = strings.ToLower(ext)
	for _, e := range executablePHPExtensions {
		if ext == e {
			return true
		}
	}
	return false
}

// IsExecutablePHPName reports whether a (lowercased) filename has an extension
// that a stock PHP handler executes. Shared by the realtime fanotify path, the
// periodic content scanners and the rule engines so none of them drift apart.
// It is a coarse, default-deny gate for content analysis only; per-directory
// .htaccess handler remappings are layered on top by the checks package.
func IsExecutablePHPName(nameLower string) bool {
	for _, ext := range executablePHPExtensions {
		if strings.HasSuffix(nameLower, ext) {
			return true
		}
	}
	return false
}

// IsPHPSourceName reports whether a file should receive PHP content analysis.
// It deliberately includes .phps even though IsExecutablePHPName does not:
// stock handlers render .phps as source, but the bytes can still hold a staged
// payload that becomes executable after a rename.
func IsPHPSourceName(nameLower string) bool {
	return IsExecutablePHPName(nameLower) || strings.HasSuffix(nameLower, ".phps")
}
